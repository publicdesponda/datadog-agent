// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package metrics

import (
	"time"

	"github.com/DataDog/datadog-agent/pkg/collector/worker"
)

// UtilizationMonitor is an interface for monitoring the utilization of a component.
type UtilizationMonitor interface {
	Start()
	Stop()
	Cancel()
}

// NoopUtilizationMonitor is a no-op implementation of UtilizationMonitor.
type NoopUtilizationMonitor struct{}

// Start does nothing.
func (n *NoopUtilizationMonitor) Start() {}

// Stop does nothing.
func (n *NoopUtilizationMonitor) Stop() {}

// Cancel does nothing.
func (n *NoopUtilizationMonitor) Cancel() {}

// TelemetryUtilizationMonitor is a UtilizationMonitor that reports utilization metrics as telemetry.
// Utilization is calculated as the ratio of time spent in use to the total time.
// Utilization can change rapidly over time based on the workload. So the monitor samples the utilization over a given interval.
type TelemetryUtilizationMonitor struct {
	name     string
	instance string
	ut       *worker.UtilizationTracker
	cancel   func()
}

// NewTelemetryUtilizationMonitor creates a new TelemetryUtilizationMonitor.
func NewTelemetryUtilizationMonitor(name, instance string) *TelemetryUtilizationMonitor {

	utilizationTracker := worker.NewUtilizationTracker("", 60*time.Second)
	cancel := startTrackerTicker(utilizationTracker, 15*time.Second)

	t := &TelemetryUtilizationMonitor{
		name:     name,
		instance: instance,
		ut:       utilizationTracker,
		cancel:   cancel,
	}
	t.startUtilizationUpdater()
	return t
}

// Start starts recording in-use time.
func (u *TelemetryUtilizationMonitor) Start() {
	u.ut.CheckStarted()
}

// Stop stops recording in-use time and reports the utilization if the sample window is met.
func (u *TelemetryUtilizationMonitor) Stop() {
	u.ut.CheckFinished()
}

// Cancel stops the monitor.
func (u *TelemetryUtilizationMonitor) Cancel() {
	u.cancel()
	u.ut.Stop()
}

func startTrackerTicker(ut *worker.UtilizationTracker, interval time.Duration) func() {
	ticker := time.NewTicker(interval)
	cancel := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer ticker.Stop()
		defer close(done)
		for {
			select {
			case <-ticker.C:
				ut.Tick()
			case <-cancel:
				return
			}
		}
	}()

	return func() {
		cancel <- struct{}{}
		<-done // make sure Tick will not be called after we return.
	}
}

func (u *TelemetryUtilizationMonitor) startUtilizationUpdater() {
	TlmUtilizationRatio.Set(0, u.name, u.instance)
	go func() {
		for value := range u.ut.Output {
			TlmUtilizationRatio.Set(value, u.name, u.instance)
		}
	}()
}
