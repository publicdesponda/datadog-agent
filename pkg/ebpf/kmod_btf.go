// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux_bpf

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// KernelModuleBTFLoadFunc is a function that accepts a kernel module name and returns the BTF for that kernel module.
type KernelModuleBTFLoadFunc func(string) (*btf.Spec, error)

// LoadKernelModuleBTF handles loading kernel module BTF for each program, if necessary
func LoadKernelModuleBTF(collSpec *ebpf.CollectionSpec, progOpts *ebpf.ProgramOptions, modLoadFunc KernelModuleBTFLoadFunc) error {
	if modLoadFunc == nil {
		return nil
	}

	for _, p := range collSpec.Programs {
		mod, err := p.KernelModule()
		if err != nil {
			return fmt.Errorf("kernel module search for %s: %w", p.AttachTo, err)
		}
		if mod == "" {
			continue
		}

		if progOpts.KernelModuleTypes == nil {
			progOpts.KernelModuleTypes = make(map[string]*btf.Spec)
		}
		if _, ok := progOpts.KernelModuleTypes[mod]; ok {
			continue
		}

		// try default BTF first
		modBTF, err := btf.LoadKernelModuleSpec(mod)
		if err != nil {
			// try callback function next
			modBTF, err = modLoadFunc(mod)
			if err != nil {
				return fmt.Errorf("kernel module BTF load for %s: %w", mod, err)
			}
		}
		progOpts.KernelModuleTypes[mod] = modBTF
	}
	return nil
}
