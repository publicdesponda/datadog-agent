// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package kprobe

import (
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"

	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode"
	"github.com/DataDog/datadog-agent/pkg/ebpf/constant"
	"github.com/DataDog/datadog-agent/pkg/ebpf/loader"
	"github.com/DataDog/datadog-agent/pkg/ebpf/telemetry"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/network/filter"
	"github.com/DataDog/datadog-agent/pkg/network/tracer/connection/util"
	"github.com/DataDog/datadog-agent/pkg/network/tracer/offsetguess"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type TracerType int

const (
	TracerTypePrebuilt TracerType = iota
	TracerTypeRuntimeCompiled
	TracerTypeCORE
)

var (
	// The kernel has to be newer than 4.11.0 since we are using bpf_skb_load_bytes (4.5.0+), which
	// was added to socket filters in 4.11.0:
	// - 2492d3b867043f6880708d095a7a5d65debcfc32
	classificationMinimumKernel = kernel.VersionCode(4, 11, 0)

	// these primarily exist for mocking out in tests
	coreTracerLoader          = loadCORETracer
	rcTracerLoader            = loadRuntimeCompiledTracer
	prebuiltTracerLoader      = loadPrebuiltTracer
	tracerLoaderFromAsset     = loadTracerFromAsset
	tracerOffsetGuesserRunner = offsetguess.TracerOffsets.Offsets

	errCORETracerNotSupported = errors.New("CO-RE tracer not supported on this platform")
)

// ClassificationSupported returns true if the current kernel version supports the classification feature.
// The kernel has to be newer than 4.7.0 since we are using bpf_skb_load_bytes (4.5.0+) method to read from the socket
// filter, and a tracepoint (4.7.0+)
func ClassificationSupported(config *config.Config) bool {
	if !config.ProtocolClassificationEnabled {
		return false
	}
	if !config.CollectTCPv4Conns && !config.CollectTCPv6Conns {
		return false
	}
	currentKernelVersion, err := kernel.HostVersion()
	if err != nil {
		log.Warn("could not determine the current kernel version. classification monitoring disabled.")
		return false
	}

	return currentKernelVersion >= classificationMinimumKernel
}

// LoadTracer loads the co-re/prebuilt/runtime compiled network tracer, depending on config
func LoadTracer(cfg *config.Config) (*loader.Collection, func() error, TracerType, error) {
	if cfg.EnableCORE {
		err := isCORETracerSupported()
		if err != nil && !errors.Is(err, errCORETracerNotSupported) {
			return nil, nil, TracerTypeCORE, fmt.Errorf("error determining if CO-RE tracer is supported: %w", err)
		}

		var coll *loader.Collection
		var closeFn func() error
		if err == nil {
			coll, closeFn, err = coreTracerLoader(cfg)
			// if it is a verifier error, bail always regardless of
			// whether a fallback is enabled in config
			var ve *ebpf.VerifierError
			if err == nil || errors.As(err, &ve) {
				return coll, closeFn, TracerTypeCORE, err
			}
		}

		if cfg.EnableRuntimeCompiler && cfg.AllowRuntimeCompiledFallback {
			log.Warnf("error loading CO-RE network tracer, falling back to runtime compiled: %s", err)
		} else if cfg.AllowPrecompiledFallback {
			log.Warnf("error loading CO-RE network tracer, falling back to pre-compiled: %s", err)
		} else {
			return nil, nil, TracerTypeCORE, fmt.Errorf("error loading CO-RE network tracer: %w", err)
		}
	}

	if cfg.EnableRuntimeCompiler && (!cfg.EnableCORE || cfg.AllowRuntimeCompiledFallback) {
		coll, closeFn, err := rcTracerLoader(cfg)
		if err == nil {
			return coll, closeFn, TracerTypeRuntimeCompiled, err
		}

		if !cfg.AllowPrecompiledFallback {
			return nil, nil, TracerTypeRuntimeCompiled, fmt.Errorf("error compiling network tracer: %w", err)
		}

		log.Warnf("error compiling network tracer, falling back to pre-compiled: %s", err)
	}

	offsets, err := tracerOffsetGuesserRunner(cfg)
	if err != nil {
		return nil, nil, TracerTypePrebuilt, fmt.Errorf("error loading prebuilt tracer: error guessing offsets: %s", err)
	}

	coll, closeFn, err := prebuiltTracerLoader(cfg, offsets)
	return coll, closeFn, TracerTypePrebuilt, err
}

type tracerLoadOptions struct {
	runtimeTracer bool
	coreTracer    bool
	modLoadFunc   ddebpf.KernelModuleBTFLoadFunc
	vmlinux       *btf.Spec
	offsets       map[string]uint64
}

func loadTracerFromAsset(buf bytecode.AssetReader, config *config.Config, opts tracerLoadOptions) (coll *loader.Collection, closeFn func() error, err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			_ = c.Close()
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, err
	}

	collSpec, err := ebpf.LoadCollectionSpecFromReader(buf)
	if err != nil {
		return nil, nil, fmt.Errorf("load collection spec: %s", err)
	}
	if opts.runtimeTracer {
		// the runtime compiled tracer has no need for separate probes targeting specific kernel versions, since it can
		// do that with #ifdefs inline. Thus, the following probes should only be declared as existing in the prebuilt
		// tracer.
		delete(collSpec.Programs, probes.TCPRetransmitPre470)
		delete(collSpec.Programs, probes.IPMakeSkbPre4180)
		delete(collSpec.Programs, probes.IP6MakeSkbPre470)
		delete(collSpec.Programs, probes.IP6MakeSkbPre5180)
		delete(collSpec.Programs, probes.UDPRecvMsgPre5190)
		delete(collSpec.Programs, probes.UDPv6RecvMsgPre5190)
		delete(collSpec.Programs, probes.UDPRecvMsgPre470)
		delete(collSpec.Programs, probes.UDPv6RecvMsgPre470)
		delete(collSpec.Programs, probes.UDPRecvMsgPre410)
		delete(collSpec.Programs, probes.UDPv6RecvMsgPre410)
		delete(collSpec.Programs, probes.UDPRecvMsgReturnPre470)
		delete(collSpec.Programs, probes.UDPv6RecvMsgReturnPre470)
		delete(collSpec.Programs, probes.TCPSendMsgPre410)
		delete(collSpec.Programs, probes.TCPRecvMsgPre410)
		delete(collSpec.Programs, probes.TCPRecvMsgPre5190)
	}

	// Use the config to determine what kernel probes should be enabled
	enabledProbes, err := enabledProbes(config, opts.runtimeTracer, opts.coreTracer)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid probe configuration: %v", err)
	}
	// exclude all non-enabled probes to ensure we don't run into problems with unsupported probe types
	for funcName := range collSpec.Programs {
		if _, enabled := enabledProbes[funcName]; !enabled {
			delete(collSpec.Programs, funcName)
		}
	}

	if config.RingBufferSupportedNPM() {
		util.EnableRingBuffers(collSpec)
	} else {
		for _, p := range collSpec.Programs {
			ddebpf.RemoveHelperCalls(p, asm.FnRingbufOutput)
		}
	}

	classificationSupported := ClassificationSupported(config)
	if !classificationSupported {
		// Kernels < 4.7.0 do not know about the per-cpu array map used
		// in classification, preventing the program to load even though
		// we won't use it. We change the type to a simple array map to
		// circumvent that.
		for _, mapName := range []string{probes.ProtocolClassificationBufMap, probes.KafkaClientIDBufMap, probes.KafkaTopicNameBufMap} {
			collSpec.Maps[mapName].Type = ebpf.Array
		}
	}

	_, udpSendPageEnabled := enabledProbes[probes.UDPSendPage]
	boolConstants := map[string]bool{
		"protocol_classification_enabled": classificationSupported,
		"tcp_failed_connections_enabled":  config.FailedConnectionsSupported(),
		"udp_send_page_enabled":           udpSendPageEnabled,
		"ringbuffers_enabled":             config.RingBufferSupportedNPM(),
	}
	for name, val := range boolConstants {
		intVal := uint64(0)
		if val {
			intVal = 1
		}
		if err := constant.EditAll(collSpec, name, intVal); err != nil {
			return nil, nil, fmt.Errorf("editing constant: %s", err)
		}
	}
	for name, val := range opts.offsets {
		if err := constant.EditAll(collSpec, name, val); err != nil {
			return nil, nil, fmt.Errorf("editing offset constant: %s", err)
		}
	}

	if err := util.EditCommonMaps(collSpec, config); err != nil {
		return nil, nil, fmt.Errorf("edit common maps: %s", err)
	}
	if err := util.EditCommonConstants(collSpec, config); err != nil {
		return nil, nil, fmt.Errorf("edit common constants: %s", err)
	}

	progOpts := ebpf.ProgramOptions{
		KernelTypes: opts.vmlinux,
	}
	if err := ddebpf.LoadKernelModuleBTF(collSpec, &progOpts, opts.modLoadFunc); err != nil {
		return nil, nil, fmt.Errorf("loading kernel module BTF: %s", err)
	}
	if err := ddebpf.PatchPrintkNewline(collSpec); err != nil {
		return nil, nil, fmt.Errorf("patch printk newline: %w", err)
	}
	collOpts := ebpf.CollectionOptions{Programs: progOpts}
	if err := telemetry.SetupErrorsTelemetry(collSpec, &collOpts); err != nil {
		return nil, nil, fmt.Errorf("setup errors telemetry: %w", err)
	}
	coll, err = loader.NewCollectionWithOptions(collSpec, collOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("load collection: %w", err)
	}
	defer closeOnError(coll)

	if err := telemetry.PostLoadSetup(coll); err != nil {
		return nil, nil, err
	}

	if classificationSupported {
		tailCalls := map[string]map[uint32]string{
			probes.ClassificationProgsMap: {
				netebpf.ClassificationQueues: probes.ProtocolClassifierQueuesSocketFilter,
				netebpf.ClassificationDBs:    probes.ProtocolClassifierDBsSocketFilter,
				netebpf.ClassificationGRPC:   probes.ProtocolClassifierGRPCSocketFilter,
			},
			probes.TCPCloseProgsMap: {
				0: probes.TCPCloseFlushReturn,
			},
		}
		for mapName, routing := range tailCalls {
			for key, progName := range routing {
				if err := coll.SetTailCall(mapName, key, progName); err != nil {
					return nil, nil, fmt.Errorf("tail call set: %s", err)
				}
			}
		}

		// ensure these programs are not attached
		// TODO should there be a different way to prevent attach?
		delete(coll.SocketFilters, probes.ProtocolClassifierQueuesSocketFilter)
		delete(coll.SocketFilters, probes.ProtocolClassifierDBsSocketFilter)
		delete(coll.SocketFilters, probes.ProtocolClassifierGRPCSocketFilter)
		delete(coll.Kprobes, probes.TCPCloseFlushReturn)

		socketFilterProbe, _ := coll.SocketFilters[probes.ProtocolClassifierEntrySocketFilter]
		if socketFilterProbe == nil {
			return nil, nil, fmt.Errorf("protocol classifier socket filter %q not found", probes.ProtocolClassifierEntrySocketFilter)
		}
		// TODO should this be during attach phase, since it isn't needed until then?
		closer, socketFD, err := filter.HeadlessSocketFilter(config)
		if err != nil {
			return nil, nil, fmt.Errorf("create protocol classifier socket: %w", err)
		}
		socketFilterProbe.FD = socketFD
		return coll, closer.Close, nil
	}
	return coll, nil, nil
}

func loadCORETracer(config *config.Config) (*loader.Collection, func() error, error) {
	var coll *loader.Collection
	var closeFn func() error
	var err error
	err = ddebpf.LoadCORENoManagerAsset(netebpf.ModuleFileName("tracer", config.BPFDebug), func(ar bytecode.AssetReader, modLoadFunc ddebpf.KernelModuleBTFLoadFunc, vmlinux *btf.Spec) error {
		opts := tracerLoadOptions{
			coreTracer:  true,
			modLoadFunc: modLoadFunc,
			vmlinux:     vmlinux,
		}
		coll, closeFn, err = tracerLoaderFromAsset(ar, config, opts)
		return err
	})
	return coll, closeFn, err
}

func loadRuntimeCompiledTracer(config *config.Config) (*loader.Collection, func() error, error) {
	buf, err := getRuntimeCompiledTracer(config)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = buf.Close() }()

	opts := tracerLoadOptions{
		runtimeTracer: true,
	}
	return tracerLoaderFromAsset(buf, config, opts)
}

func loadPrebuiltTracer(config *config.Config, offsets map[string]uint64) (*loader.Collection, func() error, error) {
	buf, err := netebpf.ReadBPFModule(config.BPFDir, config.BPFDebug)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read bpf module: %w", err)
	}
	defer func() { _ = buf.Close() }()

	kv, err := kernel.HostVersion()
	if err != nil {
		return nil, nil, fmt.Errorf("kernel version: %s", err)
	}
	// prebuilt on 5.18+ cannot support UDPv6
	if kv >= kernel.VersionCode(5, 18, 0) {
		config.CollectUDPv6Conns = false
	}

	opts := tracerLoadOptions{
		offsets: offsets,
	}
	return tracerLoaderFromAsset(buf, config, opts)
}

func isCORETracerSupported() error {
	kv, err := kernel.HostVersion()
	if err != nil {
		return err
	}
	if kv >= kernel.VersionCode(4, 4, 128) {
		return nil
	}

	platform, err := kernel.Platform()
	if err != nil {
		return err
	}

	// centos/redhat distributions we support
	// can have kernel versions < 4, and
	// CO-RE is supported there
	if platform == "centos" || platform == "redhat" {
		return nil
	}

	return errCORETracerNotSupported
}
