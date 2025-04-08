// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

package autoinstrumentation

import (
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
)

func TestFindServiceNameInPod(t *testing.T) {
	envVar := func(k, v string) corev1.EnvVar {
		return corev1.EnvVar{Name: k, Value: v}
	}

	envValueFrom := func(k, fieldPath string) corev1.EnvVar {
		return corev1.EnvVar{
			Name: k,
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: fieldPath,
				},
			},
		}
	}

	containerWithEnv := func(name string, env ...corev1.EnvVar) corev1.Container {
		return corev1.Container{Name: name, Env: env}
	}

	makePod := func(cs ...corev1.Container) *corev1.Pod {
		return &corev1.Pod{
			Spec: corev1.PodSpec{
				Containers: cs,
			},
		}
	}

	containerPointers := func(idx ...int) func(*corev1.Pod) []*corev1.Container {
		return func(pod *corev1.Pod) []*corev1.Container {
			cs := make([]*corev1.Container, len(idx))
			for i, id := range idx {
				cs[i] = &pod.Spec.Containers[id]
			}
			return cs
		}
	}

	type expectedEnvVarData struct {
		env        corev1.EnvVar
		containers func(*corev1.Pod) []*corev1.Container
	}

	testData := []struct {
		name     string
		pod      *corev1.Pod
		expected []expectedEnvVarData
	}{
		{
			name:     "one container, no env",
			pod:      makePod(containerWithEnv("c-1")),
			expected: []expectedEnvVarData{},
		},
		{
			name: "one container one env",
			pod: makePod(
				containerWithEnv("c-1", envVar("DD_SERVICE", "banana")),
			),
			expected: []expectedEnvVarData{
				{
					env:        corev1.EnvVar{Name: "DD_SERVICE", Value: "banana"},
					containers: containerPointers(0),
				},
			},
		},
		{
			name: "two containers one env",
			pod: makePod(
				containerWithEnv("c-1", envVar("DD_SERVICE", "banana")),
				containerWithEnv("c-2", envVar("DD_SERVICE", "banana")),
			),
			expected: []expectedEnvVarData{
				{
					env:        corev1.EnvVar{Name: "DD_SERVICE", Value: "banana"},
					containers: containerPointers(0, 1),
				},
			},
		},
		{
			name: "env from",
			pod: makePod(
				containerWithEnv("c-1", envValueFrom("DD_SERVICE", "some-field")),
				containerWithEnv("c-2", envValueFrom("DD_SERVICE", "some-field")),
			),
			expected: []expectedEnvVarData{
				{
					env:        envValueFrom("DD_SERVICE", "some-field"),
					containers: containerPointers(0, 1),
				},
			},
		},
		{
			name: "multiple different sources",
			pod: makePod(
				containerWithEnv("c-1", envValueFrom("DD_SERVICE", "some-field")),
				containerWithEnv("c-2", envVar("DD_SERVICE", "some-name")),
			),
			expected: []expectedEnvVarData{
				{
					env:        envValueFrom("DD_SERVICE", "some-field"),
					containers: containerPointers(0),
				},
				{
					env:        envVar("DD_SERVICE", "some-name"),
					containers: containerPointers(1),
				},
			},
		},
	}

	for _, tt := range testData {
		t.Run(tt.name, func(t *testing.T) {
			expected := make([]serviceEnvVarData, len(tt.expected))
			for idx, v := range tt.expected {
				expected[idx] = serviceEnvVarData{
					env:        v.env,
					containers: v.containers(tt.pod),
				}
			}

			out := findServiceNameEnvVarsInPod(tt.pod)
			require.ElementsMatch(t, expected, out)
		})
	}
}
