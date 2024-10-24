// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux_bpf

package constant

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// EditAll edits a constant value in all programs identified by [symbol] to [value]
func EditAll(collSpec *ebpf.CollectionSpec, symbol string, value uint64) error {
	for _, p := range collSpec.Programs {
		err := Edit(p, symbol, value)
		if err != nil {
			return err
		}
	}
	return nil
}

// Edit edits a constant value in [prog] identified by [symbol] to [value]
func Edit(prog *ebpf.ProgramSpec, symbol string, value uint64) error {
	insns := prog.Instructions
	refs := insns.ReferenceOffsets()
	indices := refs[symbol]
	if len(indices) == 0 {
		return nil
	}

	ldDWImm := asm.LoadImmOp(asm.DWord)
	for _, index := range indices {
		load := &insns[index]
		if load.OpCode != ldDWImm {
			return fmt.Errorf("symbol %v: load: found %v instead of %v", symbol, load.OpCode, ldDWImm)
		}
		load.Constant = int64(value)
	}
	return nil
}
