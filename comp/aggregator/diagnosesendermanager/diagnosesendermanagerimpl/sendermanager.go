// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

// Package diagnosesendermanagerimpl defines the sender manager for the local diagnose check
package diagnosesendermanagerimpl

import (
	"context"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/aggregator/diagnosesendermanager"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/hostname"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	tagger "github.com/DataDog/datadog-agent/comp/core/tagger/def"
	"github.com/DataDog/datadog-agent/comp/forwarder/defaultforwarder"
	"github.com/DataDog/datadog-agent/comp/forwarder/eventplatform"
	"github.com/DataDog/datadog-agent/comp/forwarder/eventplatform/eventplatformimpl"
	haagent "github.com/DataDog/datadog-agent/comp/haagent/def"
	logscompression "github.com/DataDog/datadog-agent/comp/serializer/logscompression/def"
	metricscompression "github.com/DataDog/datadog-agent/comp/serializer/metricscompression/def"
	"github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/option"
)

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fx.Provide(newDiagnoseSenderManager))
}

type dependencies struct {
	fx.In
	Log               log.Component
	Config            config.Component
	Hostname          hostname.Component
	LogsCompressor    logscompression.Component
	MetricsCompressor metricscompression.Component
	Tagger            tagger.Component
	HaAgent           haagent.Component
}

type diagnoseSenderManager struct {
	senderManager option.Option[sender.SenderManager]
	deps          dependencies
}

func newDiagnoseSenderManager(deps dependencies) diagnosesendermanager.Component {
	return &diagnoseSenderManager{deps: deps}
}

// LazyGetSenderManager gets an instance of SenderManager lazily.
func (sender *diagnoseSenderManager) LazyGetSenderManager() (sender.SenderManager, error) {
	senderManager, found := sender.senderManager.Get()
	if found {
		return senderManager, nil
	}

	hostnameDetected, err := sender.deps.Hostname.Get(context.TODO())
	if err != nil {
		return nil, sender.deps.Log.Errorf("Error while getting hostname, exiting: %v", err)
	}

	// Initializing the aggregator with a flush interval of 0 (to disable the flush goroutines)
	opts := aggregator.DefaultAgentDemultiplexerOptions()
	opts.FlushInterval = 0
	opts.DontStartForwarders = true

	log := sender.deps.Log
	config := sender.deps.Config
	haAgent := sender.deps.HaAgent
	options, err := defaultforwarder.NewOptions(config, log, nil)
	if err != nil {
		return nil, err
	}
	forwarder := defaultforwarder.NewDefaultForwarder(config, log, options)
	orchestratorForwarder := option.NewPtr[defaultforwarder.Forwarder](defaultforwarder.NoopForwarder{})
	eventPlatformForwarder := option.NewPtr[eventplatform.Forwarder](eventplatformimpl.NewNoopEventPlatformForwarder(sender.deps.Hostname, sender.deps.LogsCompressor))
	senderManager = aggregator.InitAndStartAgentDemultiplexer(
		log,
		forwarder,
		orchestratorForwarder,
		opts,
		eventPlatformForwarder,
		haAgent,
		sender.deps.MetricsCompressor,
		sender.deps.Tagger,
		hostnameDetected)

	sender.senderManager.Set(senderManager)
	return senderManager, nil
}
