// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package agentlogsanalyze implements 'logs-analyze'.
package agentlogsanalyze

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/agent/command"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	logComponent "github.com/DataDog/datadog-agent/comp/core/log"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	"github.com/DataDog/datadog-agent/pkg/api/util"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"

	"github.com/spf13/cobra"
)

// CliParams are the command-line arguments for this subcommand
type CliParams struct {
	*command.GlobalParams

	configFilePath string

	logFilePath string
}

const defaultLogFile = "/var/log/datadog/logs-agent.log"

// Commands returns a slice of subcommands for the 'agent' command.
func Commands(globalParams *command.GlobalParams) []*cobra.Command {
	cliParams := &CliParams{
		GlobalParams: globalParams,
	}

	cmd := &cobra.Command{
		Use:   "stream-logs",
		Short: "Stream the logs being processed by a running agent",
		Long:  ``,
		RunE: func(_ *cobra.Command, _ []string) error {
			return fxutil.OneShot(logsAnalyze,
				fx.Supply(cliParams),
				fx.Supply(command.GetDefaultCoreBundleParams(cliParams.GlobalParams)),
				core.Bundle(),
				fx.Supply(logComponent.LogForDaemon(string(loggerName), "log_file", params.DefaultLogFile)),
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

func streamRequest(url string, body []byte, duration time.Duration, onChunk func([]byte)) error {
	var e error
	c := util.GetClient(false)
	if duration != 0 {
		c.Timeout = duration
	}
	// Set session token
	e = util.SetAuthToken(pkgconfigsetup.Datadog())
	if e != nil {
		return e
	}

	e = util.DoPostChunked(c, url, "application/json", bytes.NewBuffer(body), onChunk)

	if e == io.EOF {
		return nil
	}
	if e != nil {
		fmt.Printf("Could not reach agent: %v \nMake sure the agent is running before requesting the logs and contact support if you continue having issues. \n", e)
	}
	return e
}

// openFileForWriting opens a file for writing
func openFileForWriting(filePath string) (*os.File, *bufio.Writer, error) {
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening file %s: %v", filePath, err)
	}
	bufWriter := bufio.NewWriter(f) // default 4096 bytes buffer
	return f, bufWriter, nil
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
