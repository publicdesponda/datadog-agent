// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

// Package filter exposes interfaces and implementations for packet capture
package filter

import (
	"encoding/binary"
	"io"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

type headlessSocketFilter struct {
	fd int
}

func (h *headlessSocketFilter) Close() error {
	if h.fd == -1 {
		return nil
	}
	err := unix.Close(h.fd)
	h.fd = -1
	runtime.SetFinalizer(h, nil)
	return err
}

// HeadlessSocketFilter creates a raw socket attached to the given socket filter.
// The underlying raw socket isn't polled and the filter is not meant to accept any packets.
// The purpose is to use this for pure eBPF packet inspection.
// TODO: After the proof-of-concept we might want to replace the SOCKET_FILTER program by a TC classifier
func HeadlessSocketFilter(cfg *config.Config) (io.Closer, int, error) {
	hsf := &headlessSocketFilter{}
	ns, err := cfg.GetRootNetNs()
	if err != nil {
		return nil, 0, err
	}
	defer ns.Close()

	err = kernel.WithNS(ns, func() error {
		hsf.fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
		if err != nil {
			return err
		}
		runtime.SetFinalizer(hsf, (*headlessSocketFilter).Close)
		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	return hsf, hsf.fd, nil
}

func htons(a uint16) uint16 {
	var arr [2]byte
	binary.NativeEndian.PutUint16(arr[:], a)
	return binary.BigEndian.Uint16(arr[:])
}
