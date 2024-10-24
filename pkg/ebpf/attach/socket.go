// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package attach

import (
	"syscall"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// socketFilter attaches the probe to the provided socket
func socketFilter(prog *ebpf.Program, socketFD int) (Link, error) {
	fd := prog.FD()
	if err := sockAttach(socketFD, fd); err != nil {
		return nil, err
	}
	return &socketLink{socketFD, fd}, nil
}

type socketLink struct {
	sockFD int
	progFD int
}

func (s *socketLink) Close() error {
	return sockDetach(s.sockFD, s.progFD)
}

func (s *socketLink) Pause() error {
	return sockDetach(s.sockFD, s.progFD)
}

func (s *socketLink) Resume() error {
	return sockAttach(s.sockFD, s.progFD)
}

func sockAttach(sockFd int, progFd int) error {
	return syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, progFd)
}

func sockDetach(sockFd int, progFd int) error {
	return syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, unix.SO_DETACH_BPF, progFd)
}
