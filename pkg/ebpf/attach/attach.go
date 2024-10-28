// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux

package attach

import (
	"fmt"

	"github.com/cilium/ebpf/link"

	"github.com/DataDog/datadog-agent/pkg/ebpf/loader"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

// Collection attaches all the programs in the collection
func Collection(coll *loader.Collection) (links []Link, err error) {
	// TODO cleanup tracefs?
	closeOnError := func(l Link) {
		if err != nil {
			_ = l.Close()
		}
	}

	for name, kprobe := range coll.Kprobes {
		if kprobe.IsReturnProbe {
			if kprobe.Options != nil && kprobe.Options.RetprobeMaxActive != 0 {
				kv, err := kernel.HostVersion()
				if err != nil {
					return nil, fmt.Errorf("kernel version: %s", err)
				}
				if kv < kernel.VersionCode(4, 12, 0) {
					// kernels < 4.12 do not support maxactive
					// added in https://github.com/torvalds/linux/commit/696ced4fb1d76802f864d8848aa4716633f83c17
					// remove the option, otherwise cilium/ebpf will return an error
					kprobe.Options.RetprobeMaxActive = 0
				}
			}

			l, err := link.Kretprobe(kprobe.AttachTo, kprobe.Program, kprobe.Options)
			if err != nil {
				return nil, fmt.Errorf("link kretprobe %s to %s: %s", name, kprobe.AttachTo, err)
			}
			defer closeOnError(l)
			links = append(links, l)
		} else {
			l, err := link.Kprobe(kprobe.AttachTo, kprobe.Program, kprobe.Options)
			if err != nil {
				return nil, fmt.Errorf("link kprobe %s to %s: %s", name, kprobe.AttachTo, err)
			}
			defer closeOnError(l)
			links = append(links, l)
		}
	}

	for name, tp := range coll.Tracepoints {
		l, err := link.Tracepoint(tp.Group, tp.Name, tp.Program, tp.Options)
		if err != nil {
			return nil, fmt.Errorf("link tracepoint %s to %s/%s: %s", name, tp.Group, tp.Name, err)
		}
		defer closeOnError(l)
		links = append(links, l)
	}

	for name, sf := range coll.SocketFilters {
		l, err := socketFilter(sf.Program, sf.FD)
		if err != nil {
			return nil, fmt.Errorf("link socket filter %s to %d: %s", name, sf.FD, err)
		}
		defer closeOnError(l)
		links = append(links, l)
	}

	for name, tp := range coll.Tracing {
		l, err := link.AttachTracing(link.TracingOptions{
			Program:    tp.Program,
			AttachType: tp.AttachType,
		})
		if err != nil {
			return nil, fmt.Errorf("link tracing program %s to %s: %w", name, tp.AttachType, err)
		}
		defer closeOnError(l)
		links = append(links, l)
	}

	return links, nil
}
