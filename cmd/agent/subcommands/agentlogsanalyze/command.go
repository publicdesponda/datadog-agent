// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package start

import (
	"context"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/agent/command"
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	logComponent "github.com/DataDog/datadog-agent/comp/core/log"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	"github.com/DataDog/datadog-agent/comp/logs"
	logsAgent "github.com/DataDog/datadog-agent/comp/logs/agent"
	"github.com/DataDog/datadog-agent/pkg/aggregator"
	pkgconfig "github.com/DataDog/datadog-agent/pkg/config"
	adScheduler "github.com/DataDog/datadog-agent/pkg/logs/schedulers/ad"
	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

type CliParams struct {
	*command.GlobalParams
	confPath string
}

const (
	// loggerName is the name of the dogstatsd logger
	loggerName pkgconfig.LoggerName = "LOGS"
)

// Commands returns a slice of subcommands for the 'agent' command.
func Commands(globalParams *command.GlobalParams) []*cobra.Command {
	cliParams := &CliParams{
		GlobalParams: globalParams,
	}

	cmd := &cobra.Command{
		Use:   "logs-analyze",
		Short: "Print logs from the logs agent to stdout",
		Long:  ``,
		RunE: func(_ *cobra.Command, _ []string) error {
			return fxutil.OneShot(logsAnalyze,
				fx.Supply(cliParams),
				fx.Supply(command.GetDefaultCoreBundleParams(cliParams.GlobalParams)),
				core.Bundle(),
			)
		},
	}

	cmd.PersistentFlags().StringVarP(&cliParams.confPath, "cfgpath", "c", "", "path to directory containing datadog.yaml")

	return []*cobra.Command{cmd}
}

func getSharedFxOption() fx.Option {
	return fx.Options(
		config.Module,
		logComponent.Module,

		// TODO: (components) - some parts of the agent (such as the logs agent) implicitly depend on the global state
		// set up by LoadComponents. In order for components to use lifecycle hooks that also depend on this global state, we
		// have to ensure this code gets run first. Once the common package is made into a component, this can be removed.
		fx.Invoke(func(lc fx.Lifecycle) {
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					// Main context passed to components
					common.MainCtx, common.MainCtxCancel = context.WithCancel(context.Background())

					// create and setup the Autoconfig instance
					common.LoadComponents(common.MainCtx, aggregator.GetSenderManager(), pkgconfig.Datadog.GetString("confd_path"))
					return nil
				},
			})
		}),
		logs.Bundle,
	)
}

type Params struct {
	DefaultLogFile string
}

func logsAnalyze(cliParams *CliParams, defaultConfPath string, defaultLogFile string, fct interface{}) error {
	params := &Params{
		DefaultLogFile: defaultLogFile,
	}
	return fxutil.OneShot(fct,
		fx.Supply(cliParams),
		fx.Supply(params),
		fx.Supply(config.NewParams(
			defaultConfPath,
			config.WithConfFilePath(cliParams.confPath),
			config.WithConfigMissingOK(true),
			config.WithConfigName("agent")),
		),
		fx.Supply(log.ForDaemon(string(loggerName), "log_file", params.DefaultLogFile)),
		getSharedFxOption(),
	)
}

func start(cliParams *CliParams, config config.Component, log log.Component, params *Params, logsAgent util.Optional[logsAgent.Component]) error {
	// Main context passed to components
	// ctx, cancel := context.WithCancel(context.Background())

	// Set up check collector

	if logsAgent, ok := logsAgent.Get(); ok {
		// TODO: (components) - once adScheduler is a component, inject it into the logs agent.
		logsAgent.AddScheduler(adScheduler.New(common.AC))
	}

	// load and run all configs in AD
	common.AC.LoadAndRun(common.MainCtx)

	// defer StopAgent(cancel, components)

	stopCh := make(chan struct{})
	// Block here until we receive a stop signal
	<-stopCh

	return nil
}
