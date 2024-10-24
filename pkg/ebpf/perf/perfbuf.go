// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux_bpf

package perf

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

type perfBuf struct {
	rdr       *perf.Reader
	getRecord func() *perf.Record
	cb        func(*perf.Record)
	lostCb    func(int, uint64)
	wgReader  sync.WaitGroup

	start sync.Once
	stop  sync.Once
}

type PerfBufferOptions struct {
	// PerfRingBufferSize - Size in bytes of the perf ring buffer. Defaults to the manager value if not set.
	PerfRingBufferSize int

	// Watermark - The reader will start processing samples once their sizes in the perf ring buffer
	// exceed this value. Must be smaller than PerfRingBufferSize. Defaults to the manager value if not set.
	Watermark int

	// The number of events required in any per CPU buffer before
	// Read will process data. This is mutually exclusive with Watermark.
	// The default is zero, which means Watermark will take precedence.
	WakeupEvents int

	// RecordHandler - Callback function called when a new record was retrieved from the perf
	// ring buffer.
	RecordHandler func(record *perf.Record)

	// LostHandler - Callback function called when one or more events where dropped by the kernel
	// because the perf ring buffer was full.
	LostHandler func(CPU int, count uint64)

	// RecordGetter - if specified this getter will be used to get a new record
	RecordGetter func() *perf.Record
}

func NewPerfBuffer(perfbufMap *ebpf.Map, opts PerfBufferOptions) (EventSource, error) {
	if opts.RecordGetter == nil || opts.RecordHandler == nil {
		return nil, fmt.Errorf("RecordGetter and RecordHandler are required options")
	}

	popts := perf.ReaderOptions{
		Watermark:    opts.Watermark,
		WakeupEvents: opts.WakeupEvents,
	}
	rdr, err := perf.NewReaderWithOptions(perfbufMap, opts.PerfRingBufferSize, popts)
	if err != nil {
		return nil, fmt.Errorf("create perfbuffer %q: %s", perfbufMap.String(), err)
	}
	return &perfBuf{
		rdr:       rdr,
		getRecord: opts.RecordGetter,
		cb:        opts.RecordHandler,
		lostCb:    opts.LostHandler,
	}, nil
}

func (pb *perfBuf) Start() {
	pb.start.Do(func() {
		pb.wgReader.Add(1)
		go func() {
			var record *perf.Record
			var err error

			for {
				record = pb.getRecord()
				if err = pb.rdr.ReadInto(record); err != nil {
					if errors.Is(err, perf.ErrClosed) {
						pb.wgReader.Done()
						return
					}
					if errors.Is(err, perf.ErrFlushed) {
						record.RawSample = record.RawSample[:0]
					} else {
						continue
					}
				}

				if record.LostSamples > 0 {
					// TODO re-add telemetry
					//if m.lostTelemetry != nil && record.CPU < len(m.lostTelemetry) {
					//	m.lostTelemetry[record.CPU].Add(record.LostSamples)
					//	// force usage to max because a sample was lost
					//	updateMaxTelemetry(m.usageTelemetry[record.CPU], uint64(m.bufferSize))
					//}
					if pb.lostCb != nil {
						pb.lostCb(record.CPU, record.LostSamples)
					}
					continue
				}

				// TODO re-add telemetry
				//if pb.usageTelemetry != nil {
				//	updateMaxTelemetry(pb.usageTelemetry, uint64(record.Remaining))
				//}
				pb.cb(record)
			}
		}()
	})
}

func (pb *perfBuf) Flush() error {
	return pb.rdr.Flush()
}

func (pb *perfBuf) Stop() error {
	var err error
	pb.stop.Do(func() {
		err = pb.rdr.Close()
		pb.wgReader.Wait()
	})
	return err
}
