// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux

package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

const bypassMapName = "program_bypassed"
const bypassOptInReference = "bypass_program"

// values used for map update to bypass/enable programs
var bypassValue any
var enableValue any

func setupBypass(collSpec *ebpf.CollectionSpec) (map[string]uint32, error) {
	if _, ok := collSpec.Maps[bypassMapName]; !ok {
		return nil, nil
	}
	maxBypassIndex := uint32(1)

	const stackOffset = -8
	// place a limit on how far we will inject from the start of a program
	// otherwise we aren't sure what register we need to save/restore, and it could inflate the number of instructions.
	const maxInstructionOffsetFromProgramStart = 1
	// setup bypass constants for all programs
	bypassIndexes := make(map[string]uint32, len(collSpec.Programs))
	for name, p := range collSpec.Programs {
		for i := 0; i < len(p.Instructions); i++ {
			ins := p.Instructions[i]
			if ins.Reference() != bypassOptInReference {
				continue
			}
			// return error here to ensure we only error on programs that do have a bypass reference
			if i > maxInstructionOffsetFromProgramStart {
				return nil, fmt.Errorf("unable to inject bypass instructions into program %s: bypass reference occurs too late in program", name)
			}
			if i > 0 && p.Instructions[i-1].Src != asm.R1 {
				return nil, fmt.Errorf("unable to inject bypass instructions into program %s: register other than r1 used before injection point", name)
			}

			bypassIndexes[name] = maxBypassIndex
			newInsns := append([]asm.Instruction{
				asm.Mov.Reg(asm.R6, asm.R1),
				// save bypass index to stack
				asm.StoreImm(asm.RFP, stackOffset, int64(maxBypassIndex), asm.Word),
				// store pointer to bypass index
				asm.Mov.Reg(asm.R2, asm.RFP),
				asm.Add.Imm(asm.R2, stackOffset),
				// load map reference
				asm.LoadMapPtr(asm.R1, 0).WithReference(bypassMapName),
				// bpf_map_lookup_elem
				asm.FnMapLookupElem.Call(),
				// if ret == 0, jump to `return 0`
				{
					OpCode:   asm.JEq.Op(asm.ImmSource),
					Dst:      asm.R0,
					Offset:   3, // jump TO return
					Constant: int64(0),
				},
				// pointer indirection of result from map lookup
				asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
				// if bypass NOT enabled, jump over return
				{
					OpCode:   asm.JEq.Op(asm.ImmSource),
					Dst:      asm.R1,
					Offset:   2, // jump over return on next instruction
					Constant: int64(0),
				},
				asm.Return(),
				// zero out used stack slot
				asm.StoreImm(asm.RFP, stackOffset, 0, asm.Word),
				asm.Mov.Reg(asm.R1, asm.R6),
			}, p.Instructions[i+1:]...)
			// necessary to keep kernel happy about source information for start of program
			newInsns[0] = newInsns[0].WithSource(ins.Source())
			p.Instructions = append(p.Instructions[:i], newInsns...)
			maxBypassIndex += 1
			break
		}
	}

	// no programs modified
	if maxBypassIndex == 1 {
		delete(collSpec.Maps, bypassMapName)
		return nil, nil
	}

	hasPerCPU := false
	if err := features.HaveMapType(ebpf.PerCPUArray); err == nil {
		hasPerCPU = true
	}

	collSpec.Maps[bypassMapName].MaxEntries = maxBypassIndex + 1

	if !hasPerCPU {
		// use scalar value for bypass/enable
		bypassValue = 1
		enableValue = 0
		return bypassIndexes, nil
	}

	// upgrade map type to per-cpu, if available
	collSpec.Maps[bypassMapName].Type = ebpf.PerCPUArray

	// allocate per-cpu slices used for bypass/enable
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	if bypassValue == nil {
		bypassValue = makeAndSet(cpus, uint32(1))
	}
	if enableValue == nil {
		enableValue = makeAndSet(cpus, uint32(0))
	}
	return bypassIndexes, nil
}

// create slice of length n and fill with fillVal
func makeAndSet[E any](n int, fillVal E) []E {
	s := make([]E, n)
	for i := range s {
		s[i] = fillVal
	}
	return s
}

type Pauser interface {
	Pause() error
	Resume() error
}

func (c *Collection) Pause() error {
	for _, kp := range c.Kprobes {
		if err := kp.Pause(); err != nil {
			return err
		}
	}
	for _, up := range c.Uprobes {
		if err := up.Pause(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Collection) Resume() error {
	for _, kp := range c.Kprobes {
		if err := kp.Resume(); err != nil {
			return err
		}
	}
	for _, up := range c.Uprobes {
		if err := up.Resume(); err != nil {
			return err
		}
	}
	return nil
}

func (k *Kprobe) Pause() error {
	if k.bypassMap == nil || k.bypassIndex == 0 {
		return nil
	}
	if err := k.bypassMap.Update(k.bypassIndex, bypassValue, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("update bypass map: %w", err)
	}
	return nil
}

func (k *Kprobe) Resume() error {
	if k.bypassMap == nil || k.bypassIndex == 0 {
		return nil
	}
	if err := k.bypassMap.Update(k.bypassIndex, enableValue, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("update bypass map: %w", err)
	}
	return nil
}

func (u *Uprobe) Pause() error {
	if u.bypassMap == nil || u.bypassIndex == 0 {
		return nil
	}
	if err := u.bypassMap.Update(u.bypassIndex, bypassValue, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("update bypass map: %w", err)
	}
	return nil
}

func (u *Uprobe) Resume() error {
	if u.bypassMap == nil || u.bypassIndex == 0 {
		return nil
	}
	if err := u.bypassMap.Update(u.bypassIndex, enableValue, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("update bypass map: %w", err)
	}
	return nil
}
