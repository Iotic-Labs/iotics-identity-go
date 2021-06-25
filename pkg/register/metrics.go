// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"github.com/prometheus/client_golang/prometheus"
)

// metrics

// MetricNamespace metric namespace
const MetricNamespace string = "iotics_identity"

// MetricSubsystem metric subsystem
const MetricSubsystem string = "resolver"

// MetricResolverErrors metric total errors
const MetricResolverErrors string = "errors_total"

// MetricErrorTypeConnection connection error
const MetricErrorTypeConnection string = "connection"

// MetricErrorTypeServer server error
const MetricErrorTypeServer string = "server"

// MetricErrorTypeTimeout timeout error
const MetricErrorTypeTimeout string = "timeout"

// MetricErrorTypeApplication application error
const MetricErrorTypeApplication string = "application"

// MetricErrorTypeNotFound application error
const MetricErrorTypeNotFound string = "notfound"

var (
	totalResolverErrors *prometheus.CounterVec
)

func init() {
	ResetMetrics()
}

// RegisterMetrics registers our metris with a registry
func RegisterMetrics(registry *prometheus.Registry) {
	registry.MustRegister(totalResolverErrors)
}

// ResetMetrics for testing
func ResetMetrics() {
	totalResolverErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricNamespace,
			Subsystem: MetricSubsystem,
			Name:      MetricResolverErrors,
			Help:      "Total resolver client errors by error type",
		}, []string{"type"},
	)
}
