// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux_bpf

package loader

import (
	"fmt"
)

func (c *Collection) SetTailCall(mapName string, key uint32, progName string) error {
	progsMap, ok := c.Maps[mapName]
	if !ok {
		return fmt.Errorf("map %s not found", mapName)
	}
	prog, ok := c.Programs[progName]
	if !ok {
		return fmt.Errorf("program %s not found", progName)
	}

	if err := progsMap.Put(key, uint32(prog.FD())); err != nil {
		return fmt.Errorf("map %s key %d: %s", mapName, key, err)
	}
	return nil
}
