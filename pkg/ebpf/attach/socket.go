// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux

package attach

import (
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// socketFilter attaches the probe to the provided socket
func socketFilter(prog *ebpf.Program, socketFD int) (Link, error) {
	fd := prog.FD()
	l := &socketLink{sockFD: socketFD, progFD: fd}
	if err := l.attach(); err != nil {
		return nil, err
	}
	return l, nil
}

type socketLink struct {
	sync.Mutex
	attached bool

	sockFD int
	progFD int
}

func (s *socketLink) Close() error {
	return s.detach()
}

func (s *socketLink) Pause() error {
	return s.detach()
}

func (s *socketLink) Resume() error {
	return s.attach()
}

func (s *socketLink) attach() error {
	s.Lock()
	defer s.Unlock()
	if s.attached {
		return nil
	}

	err := syscall.SetsockoptInt(s.sockFD, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, s.progFD)
	if err == nil {
		s.attached = true
	}
	return err
}

func (s *socketLink) detach() error {
	s.Lock()
	defer s.Unlock()
	if !s.attached {
		return nil
	}

	err := syscall.SetsockoptInt(s.sockFD, syscall.SOL_SOCKET, unix.SO_DETACH_BPF, s.progFD)
	if err == nil {
		s.attached = false
	}
	return err
}
