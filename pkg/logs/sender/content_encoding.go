// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package sender

import (
	"bytes"
	"compress/gzip"

	"github.com/DataDog/datadog-agent/pkg/logs/metrics"
)

// ContentEncoding encodes the payload
type ContentEncoding interface {
	name() string
	encode(payload []byte) ([]byte, error)
}

// IdentityContentType encodes the payload using the identity function
var IdentityContentType ContentEncoding = &identityContentType{}

type identityContentType struct{}

func (c *identityContentType) name() string {
	return "identity"
}

func (c *identityContentType) encode(payload []byte) ([]byte, error) {
	return payload, nil
}

// GzipContentEncoding encodes the payload using gzip algorithm
type GzipContentEncoding struct {
	level int
}

// NewGzipContentEncoding creates a new Gzip content type
func NewGzipContentEncoding(level int) *GzipContentEncoding {
	if level < gzip.NoCompression {
		level = gzip.NoCompression
	} else if level > gzip.BestCompression {
		level = gzip.BestCompression
	}

	return &GzipContentEncoding{
		level,
	}
}

func (c *GzipContentEncoding) name() string {
	return "gzip"
}

func (c *GzipContentEncoding) encode(payload []byte) ([]byte, error) {
	var compressedPayload bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&compressedPayload, c.level)
	if err != nil {
		return nil, err
	}
	_, err = gzipWriter.Write(payload)
	if err != nil {
		return nil, err
	}
	err = gzipWriter.Flush()
	if err != nil {
		return nil, err
	}
	err = gzipWriter.Close()
	if err != nil {
		return nil, err
	}
	return compressedPayload.Bytes(), nil
}

// AdaptiveGzipContentEncoding encodes the payload using gzip algorithm
type AdaptiveGzipContentEncoding struct {
	utilization metrics.UtilizationMonitor
	level       int
}

// NewGzipContentEncoding creates a new Gzip content type
func NewAdaptiveGzipContentEncoding(initLevel int, utilization metrics.UtilizationMonitor) *AdaptiveGzipContentEncoding {

	if initLevel < gzip.NoCompression {
		initLevel = gzip.NoCompression
	} else if initLevel > gzip.BestCompression {
		initLevel = gzip.BestCompression
	}

	return &AdaptiveGzipContentEncoding{
		utilization: utilization,
		level:       initLevel,
	}
}

func (c *AdaptiveGzipContentEncoding) name() string {
	return "gzip"
}

func (c *AdaptiveGzipContentEncoding) getWriter(payload *bytes.Buffer) (*gzip.Writer, error) {
	min := gzip.NoCompression
	max := gzip.BestCompression

	if c.utilization.GetUtilization() > 0.9 {
		c.level += 1
	} else if c.utilization.GetUtilization() < 0.5 {
		c.level -= 1
	}

	if c.level < min {
		c.level = min
	} else if c.level > max {
		c.level = max
	}

	gzipWriter, err := gzip.NewWriterLevel(payload, c.level)

	return gzipWriter, err
}

func (c *AdaptiveGzipContentEncoding) encode(payload []byte) ([]byte, error) {
	var compressedPayload bytes.Buffer
	gzipWriter, err := c.getWriter(&compressedPayload)
	if err != nil {
		return nil, err
	}
	_, err = gzipWriter.Write(payload)
	if err != nil {
		return nil, err
	}
	err = gzipWriter.Flush()
	if err != nil {
		return nil, err
	}
	err = gzipWriter.Close()
	if err != nil {
		return nil, err
	}
	return compressedPayload.Bytes(), nil
}
