// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package main is the entrypoint for the EdgeTxStatsd tool
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
)

const (
	dogstatsdHost        = "127.0.0.1"
	timeLayout           = "15:04:05.000"
	defaultMetricsPrefix = "drone."
)

var (
	quiet = flag.Bool("quiet", false, "Only return the exit code on failure.")
	tags  = []string{"environment:dev"}
)

type errorCounters struct {
	readFailedCount       uint64
	mismatchedColumnCount uint64
	badTimeStringCount    uint64
	badHexStringCount     uint64
	badValueCount         uint64
	sendFailedCount       uint64
}

func printUsage() {
	fmt.Printf("Submit data from a EdgeTX telemetry log as metrics to the local dogstatsd service\n")
	fmt.Printf("The metrics will have relative timestamps from the time of submission\n\n")
	fmt.Printf("Usage: EdgeTxLogStatsd -file <telemetry log file> [-port <dogstatsd port>] [-prefix <metrics prefix]\n\n")
	fmt.Printf("Example: EdgeTxLogStatsd -file dronelog.csv -port 8125\n")
}

func printf(format string, a ...interface{}) {
	if !*quiet {
		fmt.Printf(format, a...)
	}
}

func formatMetricName(rawHeader string, prefix string) string {
	// Remove ambiguous symbols.
	header := strings.TrimSuffix(rawHeader, ")")
	header = strings.Replace(header, "%", "percent", -1)
	header = strings.Replace(header, "(", "_", -1)
	header = strings.Replace(header, ")", "_", -1)
	header = strings.TrimSpace(header)

	return fmt.Sprintf("%s%s", prefix, header)
}

func (e *errorCounters) hasErrors() bool {
	return (e.badHexStringCount > 0 ||
		e.badTimeStringCount > 0 ||
		e.badValueCount > 0 ||
		e.mismatchedColumnCount > 0 ||
		e.readFailedCount > 0 ||
		e.sendFailedCount > 0)
}

func (e *errorCounters) printCounters() {
	printf("  Bad hex strings: %d\n", e.badHexStringCount)
	printf("  Bad time strings: %d\n", e.badTimeStringCount)
	printf("  Bad values: %d\n", e.badValueCount)
	printf("  Mismatched columns: %d\n", e.mismatchedColumnCount)
	printf("  Read failures: %d\n", e.readFailedCount)
	printf("  Send failures: %d\n", e.sendFailedCount)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	filePath := flag.String(
		"file",
		"",
		"Path to telemetry log file in .csv format")
	dogstatsdPort := flag.Int(
		"port",
		8125,
		"Port of the local dogstatsd. Default is 8125.")
	metricsPrefix := flag.String(
		"prefix",
		defaultMetricsPrefix,
		"Prefix applied to the name of metrics. Default is 'drone.'")

	flag.Parse()

	if *filePath == "" {
		log.Fatal("Missing argument for telemetry log file")
	}

	// Setup the statsd client.
	cs := fmt.Sprintf("%s:%d", dogstatsdHost, *dogstatsdPort)
	statsdClient, err := statsd.New(cs)
	if err != nil {
		log.Fatal("Failed to start statsd client", err)
	}

	submitTelemetryLogData(filePath, statsdClient, metricsPrefix)
}

// submitTelemetryLogData reads a telemetry log file in csv format, parses each row, and submits
// each value as a metric with the statsd client.
func submitTelemetryLogData(filePath *string, statsdClient *statsd.Client, metricsPrefix *string) {
	// Open the telemetry log file.
	file, err := os.Open(*filePath)
	if err != nil {
		log.Fatal("Failed to open the telemetry log file", err)
	}
	defer file.Close()

	// Setup the csv reader.
	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true
	reader.LazyQuotes = true
	reader.Comma = ','

	// Read the first line with the headers. We will these as metric names.
	rawHeaders, err := reader.Read()
	if err != nil {
		log.Fatal("Failed to read CSV headers", err)
	}

	count := len(rawHeaders)
	metricNames := []string{}

	// Format the metric names from the headers and find the columns with the date/time values.
	// We will not submit the date/time values directly since most likely they will be outside of
	// the active window of dashboards.
	dateCellIndex := -1
	timeCellIndex := -1

	for i, rawHeader := range rawHeaders {
		metricName := ""

		if rawHeader == "Date" {
			dateCellIndex = i
		} else if rawHeader == "Time" {
			timeCellIndex = i
		} else {
			metricName = formatMetricName(rawHeader, *metricsPrefix)
		}

		metricNames = append(metricNames, metricName)
	}

	var lastTimeValue time.Time
	var timestamp time.Time
	var timeDelta time.Duration
	var totalTimeDelta time.Duration
	var rowNumber uint64
	var errors errorCounters

	// Because the dashboard only shows metrics only up to the present time,
	// it will take a while for "future" metrics to show up.
	// We will use a base time of 5 minutes in the past, to allow the relative
	// timestamps and metrics to be more immediately visible within the dashboard window.
	// The exact base timestamp is not critical, it is more of a convenience.
	baseDeltaTime := time.Duration(-5 * float64(time.Minute))
	baseTimestamp := time.Now().Add(baseDeltaTime)

	// If the telemetry data has time values, we will  derive a relative timestamp for the metrics.
	buildTimestamp := timeCellIndex >= 0

	for {
		rowNumber++

		sample, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}

			printf("Error reading row %d (ignored) - %s\n", rowNumber, err)
			errors.readFailedCount++
			break
		}

		if len(sample) != count {
			printf("Mismatched column count in row %d (ignored)\n", rowNumber)
			errors.mismatchedColumnCount++
			continue
		}

		// Build a relative timestamp
		if buildTimestamp {
			timeString := sample[timeCellIndex]

			timeValue, err := time.Parse(timeLayout, timeString)
			if err != nil {
				printf("Failed to parse time from row %d (ignored) - %s\n", rowNumber, err)
				errors.badTimeStringCount++
				continue
			}

			if lastTimeValue.IsZero() {
				timeDelta = 0
			} else {
				timeDelta = timeValue.Sub(lastTimeValue)
			}

			lastTimeValue = timeValue
		} else {
			timeDelta = time.Duration(1 * float64(time.Second))
		}

		totalTimeDelta = totalTimeDelta + timeDelta
		timestamp = baseTimestamp.Add(totalTimeDelta)

		for i, value := range sample {
			if i == dateCellIndex || i == timeCellIndex {
				continue
			}

			fvalue := 0.0

			if strings.HasPrefix(value, "0x") {
				// Try to parse as hex to int
				ivalue, err := strconv.ParseUint(strings.TrimPrefix(value, "0x"), 16, 64)
				if err != nil {
					printf("Failed to parse value as hex from row %d (ignored) - %s\n", rowNumber, err)
					errors.badHexStringCount++
					continue
				}

				// Convert from int to float.
				fvalue = math.Float64frombits(uint64(ivalue))
			} else {
				// Try to parse as float or int
				fvalue, err = strconv.ParseFloat(value, 64)
				if err != nil {
					printf("Failed to parse value from row %d (ignored) - %s\n", rowNumber, err)
					errors.badValueCount++
					continue
				}
			}

			// Submit the metric.
			err = statsdClient.GaugeWithTimestamp(metricNames[i], fvalue, tags, 1, timestamp)
			if err != nil {
				printf("Failed to send data to dogstatsd (row %d)- %s\n", rowNumber, err)
				errors.sendFailedCount++
				continue
			}

			printf("Submitted: %v, %s = %f\n", timestamp, metricNames[i], fvalue)
		}
	}

	printf("Flushing...\n")
	err = statsdClient.Flush()
	if err != nil {
		log.Fatal("Failed to flush statsd", err)
	}

	if errors.hasErrors() {
		errors.printCounters()
		os.Exit(1)
	}
}
