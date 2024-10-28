// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux

package loader

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Collection struct {
	*ebpf.Collection

	Kprobes       map[string]*Kprobe
	Uprobes       map[string]*Uprobe
	SocketFilters map[string]*SocketFilter
	Tracepoints   map[string]*Tracepoint
	Tracing       map[string]*Tracing
}

type CollectionOptions struct {
	ebpf.CollectionOptions
	BypassEnabled bool
}

func (c *Collection) Close() error {
	c.Collection.Close()
	return nil
}

type Kprobe struct {
	Program       *ebpf.Program
	AttachTo      string
	IsReturnProbe bool
	Options       *link.KprobeOptions

	bypassIndex uint32
	bypassMap   *ebpf.Map
}

type Uprobe struct {
	Program       *ebpf.Program
	BinaryPath    string
	AttachTo      string
	IsReturnProbe bool
	Options       *link.UprobeOptions

	bypassIndex uint32
	bypassMap   *ebpf.Map
}

type SocketFilter struct {
	Program *ebpf.Program
	FD      int
}

type Tracepoint struct {
	Program *ebpf.Program
	Group   string
	Name    string
	Options *link.TracepointOptions
}

type Tracing struct {
	Program    *ebpf.Program
	AttachType ebpf.AttachType
}

func NewCollectionWithOptions(collSpec *ebpf.CollectionSpec, options CollectionOptions) (*Collection, error) {
	var err error
	var bypassIndexes map[string]uint32
	if options.BypassEnabled {
		bypassIndexes, err = setupBypass(collSpec)
		if err != nil {
			return nil, fmt.Errorf("setup bypass: %w", err)
		}
	}
	if len(bypassIndexes) == 0 {
		delete(collSpec.Maps, bypassMapName)
	}

	coll, err := ebpf.NewCollectionWithOptions(collSpec, options.CollectionOptions)
	if err != nil {
		return nil, fmt.Errorf("load collection: %w", err)
	}
	c := &Collection{
		Collection: coll,
	}
	bypassMap := c.Maps[bypassMapName]

	for name, prog := range coll.Programs {
		spec := collSpec.Programs[name]
		switch prog.Type() {
		case ebpf.Kprobe:
			const kprobePrefix, kretprobePrefix = "kprobe/", "kretprobe/"
			const uprobePrefix, uretprobePrefix = "uprobe/", "uretprobe/"
			switch {
			case strings.HasPrefix(spec.SectionName, kprobePrefix):
				if c.Kprobes == nil {
					c.Kprobes = map[string]*Kprobe{}
				}
				attachPoint := spec.SectionName[len(kprobePrefix):]
				c.Kprobes[name] = &Kprobe{
					Program:       prog,
					IsReturnProbe: false,
					AttachTo:      attachPoint,
					bypassIndex:   bypassIndexes[name],
					bypassMap:     bypassMap,
				}
			case strings.HasPrefix(spec.SectionName, kretprobePrefix):
				if c.Kprobes == nil {
					c.Kprobes = map[string]*Kprobe{}
				}
				attachPoint := spec.SectionName[len(kretprobePrefix):]
				c.Kprobes[name] = &Kprobe{
					Program:       prog,
					IsReturnProbe: true,
					AttachTo:      attachPoint,
					bypassIndex:   bypassIndexes[name],
					bypassMap:     bypassMap,
				}
			case strings.HasPrefix(spec.SectionName, uprobePrefix):
				if c.Uprobes == nil {
					c.Uprobes = map[string]*Uprobe{}
				}
				attachPoint := spec.SectionName[len(uprobePrefix):]
				c.Uprobes[name] = &Uprobe{
					Program:       prog,
					IsReturnProbe: false,
					AttachTo:      attachPoint,
					bypassIndex:   bypassIndexes[name],
					bypassMap:     bypassMap,
				}
			case strings.HasPrefix(spec.SectionName, uretprobePrefix):
				if c.Uprobes == nil {
					c.Uprobes = map[string]*Uprobe{}
				}
				attachPoint := spec.SectionName[len(uretprobePrefix):]
				c.Uprobes[name] = &Uprobe{
					Program:       prog,
					IsReturnProbe: true,
					AttachTo:      attachPoint,
					bypassIndex:   bypassIndexes[name],
					bypassMap:     bypassMap,
				}
			default:
				return nil, fmt.Errorf("unknown kprobe section prefix %q", spec.SectionName)
			}
		case ebpf.TracePoint:
			if c.Tracepoints == nil {
				c.Tracepoints = map[string]*Tracepoint{}
			}
			const tracepointPrefix = "tracepoint/"
			attachPoint := spec.SectionName[len(tracepointPrefix):]
			parts := strings.Split(attachPoint, "/")
			c.Tracepoints[name] = &Tracepoint{
				Program: prog,
				Group:   parts[0],
				Name:    parts[1],
			}
		case ebpf.SocketFilter:
			if c.SocketFilters == nil {
				c.SocketFilters = map[string]*SocketFilter{}
			}
			c.SocketFilters[name] = &SocketFilter{
				Program: prog,
			}
		case ebpf.Tracing:
			if c.Tracing == nil {
				c.Tracing = map[string]*Tracing{}
			}
			c.Tracing[name] = &Tracing{
				Program:    prog,
				AttachType: spec.AttachType,
			}
		default:
			return nil, fmt.Errorf("unsupported program type %s", prog.Type())
		}
	}

	return c, nil
}
