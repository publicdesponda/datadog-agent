// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux

package attach

type Link interface {
	Close() error
}

type pauser interface {
	Pause() error
	Resume() error
}

type LinkSet []Link

func (ls LinkSet) Pause() error {
	for _, l := range ls {
		if pl, ok := l.(pauser); ok {
			if err := pl.Pause(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (ls LinkSet) Resume() error {
	for _, l := range ls {
		if pl, ok := l.(pauser); ok {
			if err := pl.Resume(); err != nil {
				return err
			}
		}
	}
	return nil
}
