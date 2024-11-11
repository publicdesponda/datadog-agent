// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package metrics

import (
	"sync"
	"time"

	"github.com/VividCortex/ewma"
)

// UtilizationMonitor is an interface for monitoring the utilization of a component.
type UtilizationMonitor interface {
	Start()
	Stop()
	GetUtilization() float64
}

// NoopUtilizationMonitor is a no-op implementation of UtilizationMonitor.
type NoopUtilizationMonitor struct{}

// Start does nothing.
func (n *NoopUtilizationMonitor) Start() {}

// Stop does nothing.
func (n *NoopUtilizationMonitor) Stop() {}

// GetUtilization returns 0.
func (n *NoopUtilizationMonitor) GetUtilization() float64 {
	return 0
}

// TelemetryUtilizationMonitor is a UtilizationMonitor that reports utilization metrics as telemetry.
// Utilization is calculated as the ratio of time spent in use to the total time.
// Utilization can change rapidly over time based on the workload. So the monitor samples the utilization over a given interval.
type TelemetryUtilizationMonitor struct {
	sync.Mutex
	inUse      time.Duration
	idle       time.Duration
	startIdle  time.Time
	startInUse time.Time
	avg        ewma.MovingAverage
	name       string
	instance   string
	ticker     *time.Ticker
}

// NewTelemetryUtilizationMonitor creates a new TelemetryUtilizationMonitor.
func NewTelemetryUtilizationMonitor(name, instance string, interval time.Duration) *TelemetryUtilizationMonitor {
	return &TelemetryUtilizationMonitor{
		startIdle:  time.Now(),
		startInUse: time.Now(),
		avg:        ewma.NewMovingAverage(),
		name:       name,
		instance:   instance,
		ticker:     time.NewTicker(interval),
	}
}

// Start starts recording in-use time.
func (u *TelemetryUtilizationMonitor) Start() {
	u.Lock()
	defer u.Unlock()
	u.idle += time.Since(u.startIdle)
	u.startInUse = time.Now()
}

// Stop stops recording in-use time and reports the utilization if the sample window is met.
func (u *TelemetryUtilizationMonitor) Stop() {
	u.Lock()
	defer u.Unlock()
	u.inUse += time.Since(u.startInUse)
	u.startIdle = time.Now()
	select {
	case <-u.ticker.C:
		u.avg.Add(float64(u.inUse) / float64(u.idle+u.inUse))
		TlmUtilizationRatio.Set(u.avg.Value(), u.name, u.instance)
		u.idle = 0
		u.inUse = 0
	default:
	}

}

func (u *TelemetryUtilizationMonitor) GetUtilization() float64 {
	u.Lock()
	defer u.Unlock()
	return u.avg.Value()
}
