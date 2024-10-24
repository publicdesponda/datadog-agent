// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package telemetry

import (
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	"math"
	"slices"
	"sync"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/exp/maps"

	"github.com/DataDog/datadog-agent/pkg/ebpf/constant"
	"github.com/DataDog/datadog-agent/pkg/ebpf/loader"
	ddmaps "github.com/DataDog/datadog-agent/pkg/ebpf/maps"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	// MapErrTelemetryMap is the map storing the map error telemetry
	mapErrTelemetryMapName string = "map_err_telemetry_map"
	// HelperErrTelemetryMap is the map storing the helper error telemetry
	helperErrTelemetryMapName string = "helper_err_telemetry_map"
)

const (
	readIndx int = iota
	readUserIndx
	readKernelIndx
	skbLoadBytes
	perfEventOutput
	mapErr = math.MaxInt
)

var helperNames = map[int]string{
	readIndx:        "bpf_probe_read",
	readUserIndx:    "bpf_probe_read_user",
	readKernelIndx:  "bpf_probe_read_kernel",
	skbLoadBytes:    "bpf_skb_load_bytes",
	perfEventOutput: "bpf_perf_event_output",
}

type telemetryIndex struct {
	key  uint64
	name string
}

// ebpfErrorsTelemetry interface allows easy mocking for UTs without a need to initialize the whole ebpf sub-system and execute ebpf maps APIs
type ebpfErrorsTelemetry interface {
	sync.Locker
	setup(opts *manager.Options)
	setupCollection(opts *ebpf.CollectionOptions)
	fill(m *manager.Manager) error
	fillCollection(*loader.Collection) error
	setProbe(name string, hash uint64)
	isInitialized() bool
	forEachMapEntry(yield func(telemetryIndex, mapErrTelemetry) bool)
	forEachHelperEntry(yield func(telemetryIndex, helperErrTelemetry) bool)
}

// ebpfTelemetry struct implements ebpfErrorsTelemetry interface and contains all the maps that
// are registered to have their telemetry collected.
type ebpfTelemetry struct {
	mtx          sync.Mutex
	mapErrMap    *ddmaps.GenericMap[uint64, mapErrTelemetry]
	helperErrMap *ddmaps.GenericMap[uint64, helperErrTelemetry]
	mapKeys      map[string]uint64
	probeKeys    map[string]uint64
}

// Lock is part of the Locker interface implementation.
func (e *ebpfTelemetry) Lock() {
	e.mtx.Lock()
}

// Unlock is part of the Locker interface implementation.
func (e *ebpfTelemetry) Unlock() {
	e.mtx.Unlock()
}

func (e *ebpfTelemetry) setup(opts *manager.Options) {
	if (e.mapErrMap != nil || e.helperErrMap != nil) && opts.MapEditors == nil {
		opts.MapEditors = make(map[string]*ebpf.Map)
	}
	// if the maps have already been loaded, setup editors to point to them
	if e.mapErrMap != nil {
		opts.MapEditors[mapErrTelemetryMapName] = e.mapErrMap.Map()
	}
	if e.helperErrMap != nil {
		opts.MapEditors[helperErrTelemetryMapName] = e.helperErrMap.Map()
	}
}

func (e *ebpfTelemetry) setupCollection(opts *ebpf.CollectionOptions) {
	if (e.mapErrMap != nil || e.helperErrMap != nil) && opts.MapReplacements == nil {
		opts.MapReplacements = make(map[string]*ebpf.Map)
	}
	// if the maps have already been loaded, setup editors to point to them
	if e.mapErrMap != nil {
		opts.MapReplacements[mapErrTelemetryMapName] = e.mapErrMap.Map()
	}
	if e.helperErrMap != nil {
		opts.MapReplacements[helperErrTelemetryMapName] = e.helperErrMap.Map()
	}
}

// fill initializes the maps for holding telemetry info.
// It must be called after the manager is initialized
func (e *ebpfTelemetry) fill(m *manager.Manager) error {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	// first manager to call will populate the maps
	if e.mapErrMap == nil {
		e.mapErrMap, _ = ddmaps.GetMap[uint64, mapErrTelemetry](m, mapErrTelemetryMapName)
	}
	if e.helperErrMap == nil {
		e.helperErrMap, _ = ddmaps.GetMap[uint64, helperErrTelemetry](m, helperErrTelemetryMapName)
	}

	var mapNames []string
	for _, m := range m.Maps {
		mapNames = append(mapNames, m.Name)
	}
	if err := e.initializeMapErrTelemetryMap(mapNames); err != nil {
		return err
	}
	if err := e.initializeHelperErrTelemetryMap(); err != nil {
		return err
	}
	return nil
}

func (e *ebpfTelemetry) fillCollection(coll *loader.Collection) error {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	// first manager to call will populate the maps
	if e.mapErrMap == nil {
		e.mapErrMap, _ = ddmaps.GetCollectionMap[uint64, mapErrTelemetry](coll, mapErrTelemetryMapName)
	}
	if e.helperErrMap == nil {
		e.helperErrMap, _ = ddmaps.GetCollectionMap[uint64, helperErrTelemetry](coll, helperErrTelemetryMapName)
	}

	if err := e.initializeMapErrTelemetryMap(maps.Keys(coll.Maps)); err != nil {
		return err
	}
	if err := e.initializeHelperErrTelemetryMap(); err != nil {
		return err
	}
	return nil
}

func (e *ebpfTelemetry) setProbe(name string, hash uint64) {
	e.probeKeys[name] = hash
}

func (e *ebpfTelemetry) isInitialized() bool {
	return e.mapErrMap != nil && e.helperErrMap != nil
}

func (e *ebpfTelemetry) forEachMapEntry(yield func(index telemetryIndex, val mapErrTelemetry) bool) {
	var mval mapErrTelemetry
	for m, k := range e.mapKeys {
		err := e.mapErrMap.Lookup(&k, &mval)
		if err != nil {
			log.Debugf("failed to get telemetry for map:key %s:%d\n", m, k)
			continue
		}
		if !yield(telemetryIndex{k, m}, mval) {
			return
		}
	}
}

func (e *ebpfTelemetry) forEachHelperEntry(yield func(index telemetryIndex, val helperErrTelemetry) bool) {
	var hval helperErrTelemetry
	for probeName, k := range e.probeKeys {
		err := e.helperErrMap.Lookup(&k, &hval)
		if err != nil {
			log.Debugf("failed to get telemetry for probe:key %s:%d\n", probeName, k)
			continue
		}
		if !yield(telemetryIndex{k, probeName}, hval) {
			return
		}
	}
}

// newEBPFTelemetry initializes a new ebpfTelemetry object
func newEBPFTelemetry() ebpfErrorsTelemetry {
	errorsTelemetry = &ebpfTelemetry{
		mapKeys:   make(map[string]uint64),
		probeKeys: make(map[string]uint64),
	}
	return errorsTelemetry
}

func (e *ebpfTelemetry) initializeMapErrTelemetryMap(mapNames []string) error {
	if e.mapErrMap == nil {
		return nil
	}

	z := new(mapErrTelemetry)
	h := keyHash()
	for _, name := range mapNames {
		// Some maps, such as the telemetry maps, are
		// redefined in multiple programs.
		if _, ok := e.mapKeys[name]; ok {
			continue
		}

		key := mapKey(h, name)
		err := e.mapErrMap.Update(&key, z, ebpf.UpdateNoExist)
		if err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
			return fmt.Errorf("failed to initialize telemetry struct for map %s", name)
		}
		e.mapKeys[name] = key
	}
	return nil
}

func (e *ebpfTelemetry) initializeHelperErrTelemetryMap() error {
	if e.helperErrMap == nil {
		return nil
	}

	// the `probeKeys` get added during instruction patching, so we just try to insert entries for any that don't exist
	z := new(helperErrTelemetry)
	for p, key := range e.probeKeys {
		err := e.helperErrMap.Update(&key, z, ebpf.UpdateNoExist)
		if err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
			return fmt.Errorf("failed to initialize telemetry struct for probe %s", p)
		}
	}
	return nil
}

func SetupErrorsTelemetry(collSpec *ebpf.CollectionSpec, opts *ebpf.CollectionOptions) error {
	activateBPFTelemetry, err := ebpfTelemetrySupported()
	if err != nil {
		return err
	}
	if err := patchEBPFTelemetry(collSpec.Programs, activateBPFTelemetry, errorsTelemetry); err != nil {
		return err
	}

	if !activateBPFTelemetry {
		// we cannot exclude the telemetry maps because on some kernels, deadcode elimination hasn't removed references
		// if telemetry not enabled: leave key constants as zero, and deadcode elimination should reduce number of instructions
		return nil
	}

	if errorsTelemetry != nil {
		errorsTelemetry.setupCollection(opts)
	}

	consts := buildMapErrTelemetryConstants(maps.Keys(collSpec.Maps))
	for name, val := range consts {
		if err := constant.EditAll(collSpec, name, val); err != nil {
			return err
		}
	}
	return nil
}

func PostLoadSetup(coll *loader.Collection) error {
	if errorsTelemetry != nil {
		return errorsTelemetry.fillCollection(coll)
	}
	return nil
}

// setupForTelemetry sets up the manager to handle eBPF telemetry.
// It will patch the instructions of all the manager probes provided.
// Constants are replaced for map error and helper error keys with their respective values.
// This must be called before ebpf-manager.Manager.Init/InitWithOptions
func setupForTelemetry(m *manager.Manager, options *manager.Options, bpfTelemetry ebpfErrorsTelemetry) error {
	activateBPFTelemetry, err := ebpfTelemetrySupported()
	if err != nil {
		return err
	}
	m.InstructionPatchers = append(m.InstructionPatchers, func(m *manager.Manager) error {
		progs, err := m.GetProgramSpecs()
		if err != nil {
			return fmt.Errorf("get program specs: %s", err)
		}
		return patchEBPFTelemetry(progs, activateBPFTelemetry, bpfTelemetry)
	})

	if activateBPFTelemetry {
		// add telemetry maps to list of maps, if not present
		if !slices.ContainsFunc(m.Maps, func(x *manager.Map) bool { return x.Name == mapErrTelemetryMapName }) {
			m.Maps = append(m.Maps, &manager.Map{Name: mapErrTelemetryMapName})
		}
		if !slices.ContainsFunc(m.Maps, func(x *manager.Map) bool { return x.Name == helperErrTelemetryMapName }) {
			m.Maps = append(m.Maps, &manager.Map{Name: helperErrTelemetryMapName})
		}

		if bpfTelemetry != nil {
			bpfTelemetry.setup(options)
		}

		var mapNames []string
		for _, m := range m.Maps {
			mapNames = append(mapNames, m.Name)
		}
		consts := buildMapErrTelemetryConstants(mapNames)
		for name, val := range consts {
			options.ConstantEditors = append(options.ConstantEditors, manager.ConstantEditor{
				Name:  name,
				Value: val,
			})
		}
	}
	// we cannot exclude the telemetry maps because on some kernels, deadcode elimination hasn't removed references
	// if telemetry not enabled: leave key constants as zero, and deadcode elimination should reduce number of instructions

	return nil
}

func patchEBPFTelemetry(progs map[string]*ebpf.ProgramSpec, enable bool, bpfTelemetry ebpfErrorsTelemetry) error {
	const symbol = "telemetry_program_id_key"
	newIns := asm.Mov.Reg(asm.R1, asm.R1)
	if enable {
		newIns = asm.StoreXAdd(asm.R1, asm.R2, asm.Word)
	}
	ldDWImm := asm.LoadImmOp(asm.DWord)
	h := keyHash()
	for fn, p := range progs {
		// do constant editing of programs for helper errors post-init
		ins := p.Instructions
		if enable && bpfTelemetry != nil {
			offsets := ins.ReferenceOffsets()
			indices := offsets[symbol]
			if len(indices) > 0 {
				for _, index := range indices {
					load := &ins[index]
					if load.OpCode != ldDWImm {
						return fmt.Errorf("symbol %v: load: found %v instead of %v", symbol, load.OpCode, ldDWImm)
					}
					key := probeKey(h, fn)
					load.Constant = int64(key)
					bpfTelemetry.setProbe(fn, key)
				}
			}
		}

		// patch telemetry helper calls
		const ebpfTelemetryPatchCall = -1
		iter := ins.Iterate()
		for iter.Next() {
			ins := iter.Ins
			if !ins.IsBuiltinCall() || ins.Constant != ebpfTelemetryPatchCall {
				continue
			}
			*ins = newIns.WithMetadata(ins.Metadata)
		}
	}
	return nil
}

func buildMapErrTelemetryConstants(mapNames []string) map[string]uint64 {
	keys := make(map[string]uint64)
	h := keyHash()
	for _, name := range mapNames {
		keys[name+"_telemetry_key"] = mapKey(h, name)
	}
	return keys
}

func keyHash() hash.Hash64 {
	return fnv.New64a()
}

func mapKey(h hash.Hash64, name string) uint64 {
	h.Reset()
	_, _ = h.Write([]byte(name))
	return h.Sum64()
}

func probeKey(h hash.Hash64, funcName string) uint64 {
	h.Reset()
	_, _ = h.Write([]byte(funcName))
	return h.Sum64()
}

// ebpfTelemetrySupported returns whether eBPF telemetry is supported, which depends on the verifier in 4.14+
func ebpfTelemetrySupported() (bool, error) {
	kversion, err := kernel.HostVersion()
	if err != nil {
		return false, err
	}
	return kversion >= kernel.VersionCode(4, 14, 0), nil
}
