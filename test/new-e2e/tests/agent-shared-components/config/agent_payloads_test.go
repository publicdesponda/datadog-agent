// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	awshost "github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments/aws/host"
	"github.com/DataDog/test-infra-definitions/components/datadog/agentparams"
	remoteComp "github.com/DataDog/test-infra-definitions/components/remote"
	"github.com/pulumi/pulumi-docker/sdk/v4/go/docker"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"testing"

	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
)

const disablePayloads = `
default_payloads.enabled: false
`

const containerCollectAll = `
logs_config:
	config_container_collect_all: true
`

type payloadsHost struct {
	environments.Host
}
type configPayloadsSuite struct {
	e2e.BaseSuite[environments.Host]
}

func WithFloggerResource(ctx *pulumi.Context, host *remoteComp.Host, dependsOnResources ...pulumi.Resource) (err error) {

	args := docker.ProviderArgs{
		Host: pulumi.Sprintf("ssh://%s@%s:22", host.Username, host.Address),
	}
	remoteDocker, err := docker.NewProvider(ctx, "remote-docker", &args)
	if err != nil {
		return err
	}
	_, err = docker.NewContainer(ctx, defaultVMName, &docker.ContainerArgs{
		Image:  pulumi.String("mingrammer/flog"),
		Attach: pulumi.Bool(false),
		Command: pulumi.StringArray{
			pulumi.String("--loop"),
		},
	}, pulumi.Providers(remoteDocker), pulumi.DependsOn(dependsOnResources))
	return err
}

func TestConfigPayloadsSuite(t *testing.T) {
	t.Parallel()
	agentOptions := []agentparams.Option{
		agentparams.WithLogs(),
		//agentparams.WithExtraAgentConfig(
		//	disablePayloads,
		//	containerCollectAll,
		//),
	}
	suiteParams := []e2e.SuiteOption{
		e2e.WithProvisioner(awshost.Provisioner(
			awshost.WithDocker(),
			awshost.WithCustomResources(WithFloggerResource),
			awshost.WithAgentOptions(agentOptions...))),
		e2e.WithDevMode(),
	}
	e2e.Run(t, &configPayloadsSuite{}, suiteParams...)
}

func (s *configPayloadsSuite) TestLogsCollectionOnly() {
	s.True(s.Env().Agent.Client.IsReady())
}

const (
	provisionerBaseID = "aws-ec2vm-"
	defaultVMName     = "flogger"
)
