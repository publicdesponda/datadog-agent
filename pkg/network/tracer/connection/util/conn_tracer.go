// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

// Package util contains common helpers used in the creation of the closed connection event handler
package util

import (
	"fmt"
	"math/bits"
	"os"

	cebpf "github.com/cilium/ebpf"

	"github.com/DataDog/datadog-agent/pkg/ebpf/constant"
	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/process/util"
)

// round x up to the nearest power of 2
func roundUpNearestPow2(x uint32) uint32 {
	return uint32(1) << bits.Len32(x-1)
}

// EnableRingBuffers sets up the ring buffer for closed connection events
func EnableRingBuffers(collSpec *cebpf.CollectionSpec) {
	numCPUs, err := cebpf.PossibleCPU()
	if err != nil {
		numCPUs = 1
	}
	ringBufSize := 8 * roundUpNearestPow2(uint32(numCPUs)) * uint32(os.Getpagesize())

	connMapSpec := collSpec.Maps[probes.ConnCloseEventMap]
	connMapSpec.Type = cebpf.RingBuf
	connMapSpec.MaxEntries = ringBufSize
	connMapSpec.KeySize = 0
	connMapSpec.ValueSize = 0

	failedMapSpec := collSpec.Maps[probes.FailedConnEventMap]
	failedMapSpec.Type = cebpf.RingBuf
	failedMapSpec.MaxEntries = ringBufSize
	failedMapSpec.KeySize = 0
	failedMapSpec.ValueSize = 0
}

// EditCommonMaps sets up common map attributes for all tracers
func EditCommonMaps(collSpec *cebpf.CollectionSpec, config *config.Config) error {
	mapNames := []string{
		probes.ConnMap,
		probes.TCPStatsMap,
		probes.TCPRetransmitsMap,
		probes.PortBindingsMap,
		probes.UDPPortBindingsMap,
		probes.ConnectionProtocolMap,
		probes.ConnectionTupleToSocketSKBConnMap,
		probes.TCPOngoingConnectPid,
	}
	for _, name := range mapNames {
		m, ok := collSpec.Maps[name]
		if !ok {
			return fmt.Errorf("map %s not found", name)
		}
		m.MaxEntries = config.MaxTrackedConnections
	}
	return nil
}

func boolToUint64(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// EditCommonConstants sets up common constants for all tracers
func EditCommonConstants(collSpec *cebpf.CollectionSpec, cfg *config.Config) error {
	begin, end := network.EphemeralRange()
	consts := map[string]uint64{
		"ephemeral_range_begin": uint64(begin),
		"ephemeral_range_end":   uint64(end),
		"tcpv6_enabled":         boolToUint64(cfg.CollectTCPv6Conns),
		"udpv6_enabled":         boolToUint64(cfg.CollectUDPv6Conns),
	}
	for name, val := range consts {
		if err := constant.EditAll(collSpec, name, val); err != nil {
			return fmt.Errorf("edit constant %s: %s", name, err)
		}
	}
	return nil
}

// ConnStatsToTuple converts a ConnectionStats to a ConnTuple
func ConnStatsToTuple(c *network.ConnectionStats, tup *netebpf.ConnTuple) {
	tup.Sport = c.SPort
	tup.Dport = c.DPort
	tup.Netns = c.NetNS
	tup.Pid = c.Pid
	if c.Family == network.AFINET {
		tup.SetFamily(netebpf.IPv4)
	} else {
		tup.SetFamily(netebpf.IPv6)
	}
	if c.Type == network.TCP {
		tup.SetType(netebpf.TCP)
	} else {
		tup.SetType(netebpf.UDP)
	}
	if c.Source.IsValid() {
		tup.Saddr_l, tup.Saddr_h = util.ToLowHigh(c.Source)
	}
	if c.Dest.IsValid() {
		tup.Daddr_l, tup.Daddr_h = util.ToLowHigh(c.Dest)
	}
}
