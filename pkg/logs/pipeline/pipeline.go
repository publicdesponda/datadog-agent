// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//nolint:revive // TODO(AML) Fix revive linter
package pipeline

import (
	"context"
	"fmt"
	"sync"

	"github.com/DataDog/datadog-agent/comp/core/hostname/hostnameimpl"
	"github.com/DataDog/datadog-agent/comp/core/hostname/hostnameinterface"
	"github.com/DataDog/datadog-agent/comp/logs/agent/config"
	pkgconfigmodel "github.com/DataDog/datadog-agent/pkg/config/model"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/logs/client"
	"github.com/DataDog/datadog-agent/pkg/logs/client/http"
	"github.com/DataDog/datadog-agent/pkg/logs/client/tcp"
	"github.com/DataDog/datadog-agent/pkg/logs/diagnostic"
	"github.com/DataDog/datadog-agent/pkg/logs/internal/decoder"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/logs/processor"
	"github.com/DataDog/datadog-agent/pkg/logs/sender"
	"github.com/DataDog/datadog-agent/pkg/logs/sources"
	"github.com/DataDog/datadog-agent/pkg/logs/status/statusinterface"
	status "github.com/DataDog/datadog-agent/pkg/logs/status/utils"
	tailer "github.com/DataDog/datadog-agent/pkg/logs/tailers/file"
)

// Pipeline processes and sends messages to the backend
type Pipeline struct {
	InputChan  chan *message.Message
	flushChan  chan struct{}
	processor  *processor.Processor
	strategy   sender.Strategy
	sender     *sender.Sender
	serverless bool
	flushWg    *sync.WaitGroup
}

// NewPipeline returns a new Pipeline
func NewPipeline(outputChan chan *message.Payload,
	processingRules []*config.ProcessingRule,
	endpoints *config.Endpoints,
	destinationsContext *client.DestinationsContext,
	diagnosticMessageReceiver diagnostic.MessageReceiver,
	serverless bool,
	pipelineID int,
	status statusinterface.Status,
	hostname hostnameinterface.Component,
	cfg pkgconfigmodel.Reader) *Pipeline {

	var senderDoneChan chan *sync.WaitGroup
	var flushWg *sync.WaitGroup
	if serverless {
		senderDoneChan = make(chan *sync.WaitGroup)
		flushWg = &sync.WaitGroup{}
	}

	mainDestinations := getDestinations(endpoints, destinationsContext, pipelineID, serverless, senderDoneChan, status, cfg)

	strategyInput := make(chan *message.Message, config.ChanSize)
	senderInput := make(chan *message.Payload, 1) // Only buffer 1 message since payloads can be large
	flushChan := make(chan struct{})

	var logsSender *sender.Sender

	var encoder processor.Encoder
	if serverless {
		encoder = processor.JSONServerlessEncoder
	} else if endpoints.UseHTTP {
		encoder = processor.JSONEncoder
	} else if endpoints.UseProto {
		encoder = processor.ProtoEncoder
	} else {
		encoder = processor.RawEncoder
	}

	strategy := getStrategy(strategyInput, senderInput, flushChan, endpoints, serverless, flushWg, pipelineID)
	logsSender = sender.NewSender(cfg, senderInput, outputChan, mainDestinations, config.DestinationPayloadChanSize, senderDoneChan, flushWg)

	inputChan := make(chan *message.Message, config.ChanSize)

	processor := processor.New(cfg, inputChan, strategyInput, processingRules,
		encoder, diagnosticMessageReceiver, hostname, pipelineID)

	return &Pipeline{
		InputChan:  inputChan,
		flushChan:  flushChan,
		processor:  processor,
		strategy:   strategy,
		sender:     logsSender,
		serverless: serverless,
		flushWg:    flushWg,
	}
}

// Start launches the pipeline
func (p *Pipeline) Start() {
	p.sender.Start()
	p.strategy.Start()
	p.processor.Start()
}

// Stop stops the pipeline
func (p *Pipeline) Stop() {
	p.processor.Stop()
	p.strategy.Stop()
	p.sender.Stop()
}

// Flush flushes synchronously the processor and sender managed by this pipeline.
func (p *Pipeline) Flush(ctx context.Context) {
	p.flushChan <- struct{}{}
	p.processor.Flush(ctx) // flush messages in the processor into the sender

	if p.serverless {
		// Wait for the logs sender to finish sending payloads to all destinations before allowing the flush to finish
		p.flushWg.Wait()
	}
}

func getDestinations(endpoints *config.Endpoints, destinationsContext *client.DestinationsContext, pipelineID int, serverless bool, senderDoneChan chan *sync.WaitGroup, status statusinterface.Status, cfg pkgconfigmodel.Reader) *client.Destinations {
	reliable := []client.Destination{}
	additionals := []client.Destination{}

	if endpoints.UseHTTP {
		for i, endpoint := range endpoints.GetReliableEndpoints() {
			telemetryName := fmt.Sprintf("logs_%d_reliable_%d", pipelineID, i)
			if serverless {
				reliable = append(reliable, http.NewSyncDestination(endpoint, http.JSONContentType, destinationsContext, senderDoneChan, telemetryName, cfg))
			} else {
				reliable = append(reliable, http.NewDestination(endpoint, http.JSONContentType, destinationsContext, endpoints.BatchMaxConcurrentSend, true, telemetryName, cfg))
			}
		}
		for i, endpoint := range endpoints.GetUnReliableEndpoints() {
			telemetryName := fmt.Sprintf("logs_%d_unreliable_%d", pipelineID, i)
			if serverless {
				additionals = append(additionals, http.NewSyncDestination(endpoint, http.JSONContentType, destinationsContext, senderDoneChan, telemetryName, cfg))
			} else {
				additionals = append(additionals, http.NewDestination(endpoint, http.JSONContentType, destinationsContext, endpoints.BatchMaxConcurrentSend, false, telemetryName, cfg))
			}
		}
		return client.NewDestinations(reliable, additionals)
	}
	for _, endpoint := range endpoints.GetReliableEndpoints() {
		reliable = append(reliable, tcp.NewDestination(endpoint, endpoints.UseProto, destinationsContext, !serverless, status))
	}
	for _, endpoint := range endpoints.GetUnReliableEndpoints() {
		additionals = append(additionals, tcp.NewDestination(endpoint, endpoints.UseProto, destinationsContext, false, status))
	}

	return client.NewDestinations(reliable, additionals)
}

//nolint:revive // TODO(AML) Fix revive linter
func getStrategy(inputChan chan *message.Message, outputChan chan *message.Payload, flushChan chan struct{}, endpoints *config.Endpoints, serverless bool, flushWg *sync.WaitGroup, _ int) sender.Strategy {
	if endpoints.UseHTTP || serverless {
		encoder := sender.IdentityContentType
		if endpoints.Main.UseCompression {
			encoder = sender.NewGzipContentEncoding(endpoints.Main.CompressionLevel)
		}
		return sender.NewBatchStrategy(inputChan, outputChan, flushChan, serverless, flushWg, sender.ArraySerializer, endpoints.BatchWait, endpoints.BatchMaxSize, endpoints.BatchMaxContentSize, "logs", encoder)
	}
	return sender.NewStreamStrategy(inputChan, outputChan, sender.IdentityContentType)
}

func stub() {

	// load a config
	// start a pipeline
	// read the file
	// print it out

	// The file could be from a command line argument, we can just open this file
	// agent logs-test /path/to/file.log
	// .               ^^^^^^^^^^^^^^^^^

	inputChan := make(chan *message.Message, 1)

	path := "./test-log-file.log" // Default file for testing
	sources := sources.NewLogSources()
	allSources := sources.GetSources() //Does the log source matter?
	file := tailer.NewFile(path, allSources[0], false)
	tailer := createTailer(file, inputChan) // tailer comes with the decoder

	var offset int64
	var whence int

	offset, whence = 0, 0
	err := tailer.Start(offset, whence)
	if err != nil {
		fmt.Println("wack error")
	}
	// the processor executes rules (e.g exclusion rules, all the log processing rules)
	// need to fill out processingRules (config)
	processingRules, _ := config.GlobalProcessingRules(pkgconfigsetup.Datadog())

	encoder := processor.JSONEncoder //might be the wrong encoder

	output := make(chan *message.Message, 1)
	processor := processor.New(pkgconfigsetup.Datadog(), inputChan, output, processingRules,
		encoder, nil, hostnameimpl.NewHostnameService(), 0)

	processor.Start()

	// print to console from output channel
	msg := <-output
	fmt.Println("wacktest Processed Log Message:", string(msg.GetContent()))

}

func createTailer(file *tailer.File, outputChan chan *message.Message) *tailer.Tailer {
	tailerInfo := status.NewInfoRegistry()

	tailerOptions := &tailer.TailerOptions{
		OutputChan:    outputChan,
		File:          file,
		SleepDuration: 0,
		Decoder:       decoder.NewDecoderFromSource(file.Source, tailerInfo),
		Info:          tailerInfo,
		TagAdder:      nil,
	}

	return tailer.NewTailer(tailerOptions)
}
