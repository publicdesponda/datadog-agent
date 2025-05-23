// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package infraattributesprocessor

import (
	"context"
	"github.com/DataDog/datadog-agent/comp/otelcol/otlp/testutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/processor/processortest"
)

func hostGetter(_ context.Context) (string, error) {
	return "test-host", nil
}

func TestType(t *testing.T) {
	tc := testutil.NewTestTaggerClient()
	factory := NewFactoryForAgent(tc, hostGetter)
	pType := factory.Type()

	assert.Equal(t, pType, Type)
}

func TestCreateDefaultConfig(t *testing.T) {
	tc := testutil.NewTestTaggerClient()
	factory := NewFactoryForAgent(tc, hostGetter)
	cfg := factory.CreateDefaultConfig()
	assert.NoError(t, componenttest.CheckConfigStruct(cfg))
}

func TestCreateProcessors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		configName string
		succeed    bool
	}{
		{
			configName: "logs_strict.yaml",
			succeed:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.configName, func(t *testing.T) {
			cm, err := confmaptest.LoadConf(filepath.Join("testdata", tt.configName))
			require.NoError(t, err)
			tc := testutil.NewTestTaggerClient()

			for k := range cm.ToStringMap() {
				// Check if all processor variations that are defined in test config can be actually created
				factory := NewFactoryForAgent(tc, func(_ context.Context) (string, error) {
					return "test-host", nil
				})
				cfg := factory.CreateDefaultConfig()

				sub, err := cm.Sub(k)
				require.NoError(t, err)
				require.NoError(t, sub.Unmarshal(&cfg))

				tp, tErr := factory.CreateTraces(
					context.Background(),
					processortest.NewNopSettings(Type),
					cfg, consumertest.NewNop(),
				)
				mp, mErr := factory.CreateMetrics(
					context.Background(),
					processortest.NewNopSettings(Type),
					cfg,
					consumertest.NewNop(),
				)
				if strings.Contains(tt.configName, "traces") {
					assert.Equal(t, tt.succeed, tp != nil)
					assert.Equal(t, tt.succeed, tErr == nil)

					assert.NotNil(t, mp)
					assert.Nil(t, mErr)
				} else {
					// Should not break configs with no trace data
					assert.NotNil(t, tp)
					assert.Nil(t, tErr)

					assert.Equal(t, tt.succeed, mp != nil)
					assert.Equal(t, tt.succeed, mErr == nil)
				}
			}
		})
	}
}
