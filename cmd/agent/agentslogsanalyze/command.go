// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package agentlogsanalyze implements 'logs-analyze'.
package agentlogsanalyze

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/fx"

	"github.com/spf13/cobra"

	"github.com/DataDog/datadog-agent/cmd/agent/command"
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	logComponent "github.com/DataDog/datadog-agent/comp/core/log/fx"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/comp/logs"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// CliParams are the command-line arguments for this subcommand
type CliParams struct {
	*command.GlobalParams

	configFilePath string

	logFilePath string
}

const defaultLogFile = "/var/log/datadog/logs-agent.log"

type Params struct {
	DefaultLogFile string
}

func getSharedFxOption() fx.Option {
	return fx.Options(
		config.Module(),
		logComponent.Module(),
		fx.Invoke(func(lc fx.Lifecycle) {
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					// Main context passed to components

					// create and setup the Autoconfig instance
					common.LoadComponents(nil, workloadmeta.Component, nil, nil)
					return nil
				},
			})
		}),
		logs.Bundle(),
	)
}

// Commands returns a slice of subcommands for the 'agent' command.
func Commands(globalParams *command.GlobalParams) []*cobra.Command {
	cliParams := &CliParams{
		GlobalParams: globalParams,
	}
	params := &Params{
		DefaultLogFile: defaultLogFile,
	}

	cmd := &cobra.Command{
		Use:   "stream-logs",
		Short: "Stream the logs being processed by a running agent",
		Long:  ``,
		RunE: func(_ *cobra.Command, _ []string) error {
			return fxutil.OneShot(logsAnalyze,
				fx.Supply(cliParams),
				fx.Supply(params),
				fx.Supply(workloadmeta),
				fx.Supply(command.GetDefaultCoreBundleParams(cliParams.GlobalParams)),
				core.Bundle(),
				fx.Supply(log.ForDaemon("LOGS", "log_file", params.DefaultLogFile)),
				getSharedFxOption(),
			)
		},
	}

	cmd.PersistentFlags().StringVarP(&cliParams.configFilePath, "cfgpath", "c", "", "path to directory containing datadog.yaml")

	// TODO add log flag
	return []*cobra.Command{cmd}
}

//nolint:revive // TODO(AML) Fix revive linter
func logsAnalyze(logComponent log.Component, config config.Component, cliParams *CliParams) error {
	ipcAddress, err := pkgconfigsetup.GetIPCAddress(pkgconfigsetup.Datadog())
	if err != nil {
		return err
	}

	if err != nil {
		return err
	}

	urlstr := fmt.Sprintf("https://%v:%v/agent/stream-logs", ipcAddress, config.GetInt("cmd_port"))

	var f *os.File
	var bufWriter *bufio.Writer

	if cliParams.configFilePath != "" {
		err = checkDirExists(cliParams.configFilePath)
		if err != nil {
			return fmt.Errorf("error creating directory for file %s: %v", cliParams.configFilePath, err)
		}

		f, bufWriter, err = openFileForWriting(cliParams.configFilePath)
		if err != nil {
			return fmt.Errorf("error opening file %s for writing: %v", cliParams.configFilePath, err)
		}
		defer func() {
			err := bufWriter.Flush()
			if err != nil {
				fmt.Printf("Error flushing buffer for log stream: %v", err)
			}
			f.Close()
		}()
	}

	return streamRequest(urlstr, body, cliParams.Duration, func(chunk []byte) {
		if bufWriter != nil {
			if _, err = bufWriter.Write(chunk); err != nil {
				fmt.Printf("Error writing stream-logs to file %s: %v", cliParams.FilePath, err)
			}
		}
	})
}

// checkDirExists checks if the directory for the given path exists, if not then create it.
func checkDirExists(path string) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}
