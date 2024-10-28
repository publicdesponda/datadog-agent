// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package fentry

import (
	"errors"
	"fmt"
	"os"
	"syscall"

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
	"github.com/DataDog/datadog-agent/pkg/network/tracer/connection/util"
	"github.com/DataDog/datadog-agent/pkg/util/fargate"
)

var ErrorNotSupported = errors.New("fentry tracer is only supported on Fargate")

// LoadTracer loads a new tracer
func LoadTracer(config *config.Config) (*loader.Collection, func() error, error) {
	if !fargate.IsFargateInstance() {
		return nil, nil, ErrorNotSupported
	}

	var coll *loader.Collection
	err := ddebpf.LoadCORENoManagerAsset(netebpf.ModuleFileName("tracer-fentry", config.BPFDebug), func(buf bytecode.AssetReader, modLoadFunc ddebpf.KernelModuleBTFLoadFunc, vmlinux *btf.Spec) error {
		if err := rlimit.RemoveMemlock(); err != nil {
			return err
		}

		collSpec, err := ebpf.LoadCollectionSpecFromReader(buf)
		if err != nil {
			return fmt.Errorf("load collection spec: %s", err)
		}

		// Use the config to determine what kernel probes should be enabled
		enabledProbes, err := enabledPrograms(config)
		if err != nil {
			return fmt.Errorf("invalid probe configuration: %v", err)
		}
		// exclude all non-enabled probes to ensure we don't run into problems with unsupported probe types
		for funcName := range collSpec.Programs {
			if _, enabled := enabledProbes[funcName]; !enabled {
				delete(collSpec.Programs, funcName)
			}
		}

		if !config.RingBufferSupportedNPM() {
			for _, p := range collSpec.Programs {
				ddebpf.RemoveHelperCalls(p, asm.FnRingbufOutput)
			}
		}

		file, err := os.Stat("/proc/self/ns/pid")
		if err != nil {
			return fmt.Errorf("could not load sysprobe pid: %w", err)
		}
		device := file.Sys().(*syscall.Stat_t).Dev
		inode := file.Sys().(*syscall.Stat_t).Ino
		if err := constant.EditAll(collSpec, "systemprobe_device", device); err != nil {
			return fmt.Errorf("edit constant: %s", err)
		}
		if err := constant.EditAll(collSpec, "systemprobe_ino", inode); err != nil {
			return fmt.Errorf("edit constant: %s", err)
		}

		ringbufferEnabled := config.RingBufferSupportedNPM()
		if ringbufferEnabled {
			util.EnableRingBuffers(collSpec)
			if err := constant.EditAll(collSpec, "ringbuffers_enabled", 1); err != nil {
				return fmt.Errorf("edit constant: %s", err)
			}
		}

		if err := util.EditCommonMaps(collSpec, config); err != nil {
			return fmt.Errorf("edit common maps: %s", err)
		}
		if err := util.EditCommonConstants(collSpec, config); err != nil {
			return fmt.Errorf("edit common constants: %s", err)
		}

		progOpts := ebpf.ProgramOptions{
			KernelTypes: vmlinux,
		}
		if err := ddebpf.LoadKernelModuleBTF(collSpec, &progOpts, modLoadFunc); err != nil {
			return fmt.Errorf("error loading kernel module BTF: %s", err)
		}
		if err := ddebpf.PatchPrintkNewline(collSpec); err != nil {
			return fmt.Errorf("patch printk newline: %w", err)
		}
		opts := ebpf.CollectionOptions{Programs: progOpts}
		if err := telemetry.SetupErrorsTelemetry(collSpec, &opts); err != nil {
			return fmt.Errorf("setup errors telemetry: %w", err)
		}
		coll, err = loader.NewCollectionWithOptions(collSpec, loader.CollectionOptions{
			CollectionOptions: opts,
			BypassEnabled:     config.BypassEnabled,
		})
		if err != nil {
			return err
		}
		if err := telemetry.PostLoadSetup(coll); err != nil {
			_ = coll.Close()
			return err
		}
		return nil
	})

	if err != nil {
		return nil, nil, err
	}
	return coll, nil, nil
}
