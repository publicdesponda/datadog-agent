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
	"github.com/cilium/ebpf/ringbuf"
)

type ringBuf struct {
	rdr       *ringbuf.Reader
	getRecord func() *ringbuf.Record
	cb        func(*ringbuf.Record)
	wgReader  sync.WaitGroup

	start sync.Once
	stop  sync.Once
}

func NewRingBuffer(ringbufMap *ebpf.Map, recordGetter func() *ringbuf.Record, cb func(*ringbuf.Record)) (EventSource, error) {
	rdr, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return nil, fmt.Errorf("create ringbuffer %q: %s", ringbufMap.String(), err)
	}
	return &ringBuf{
		rdr:       rdr,
		getRecord: recordGetter,
		cb:        cb,
	}, nil
}

func (rb *ringBuf) Start() {
	rb.start.Do(func() {
		rb.wgReader.Add(1)
		go func() {
			var record *ringbuf.Record
			var err error

			for {
				record = rb.getRecord()
				if err = rb.rdr.ReadInto(record); err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						rb.wgReader.Done()
						return
					}
					if errors.Is(err, ringbuf.ErrFlushed) {
						record.RawSample = record.RawSample[:0]
					} else {
						continue
					}
				}

				// TODO re-add telemetry
				//if rb.usageTelemetry != nil {
				//	updateMaxTelemetry(rb.usageTelemetry, uint64(record.Remaining))
				//}
				rb.cb(record)
			}
		}()
	})
}

func (rb *ringBuf) Flush() error {
	return rb.rdr.Flush()
}

func (rb *ringBuf) Stop() error {
	var err error
	rb.stop.Do(func() {
		err = rb.rdr.Close()
		rb.wgReader.Wait()
	})
	return err
}
