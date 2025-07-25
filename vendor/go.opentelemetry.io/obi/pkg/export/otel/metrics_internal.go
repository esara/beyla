// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"log/slog"
	"runtime"
	"time"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"

	"go.opentelemetry.io/otel/attribute"
	instrument "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"

	"go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
)

// InternalMetricsReporter is an internal metrics Reporter that exports to OTEL
type InternalMetricsReporter struct {
	ctx                   context.Context
	tracerFlushes         instrument.Float64Histogram
	otelMetricExports     instrument.Float64Counter
	otelMetricExportErrs  instrument.Float64Counter
	otelTraceExports      instrument.Float64Counter
	otelTraceExportErrs   instrument.Float64Counter
	instrumentedProcesses instrument.Int64UpDownCounter
	beylaInfo             instrument.Int64Gauge
}

func imlog() *slog.Logger {
	return slog.With("component", "otel.InternalMetricsReporter")
}

func NewInternalMetricsReporter(ctx context.Context, ctxInfo *global.ContextInfo, metrics *MetricsConfig) (*InternalMetricsReporter, error) {
	log := imlog()
	log.Debug("instantiating internal metrics exporter provider")
	exporter, err := InstantiateMetricsExporter(ctx, metrics, log)
	if err != nil {
		log.Error("can't instantiate metrics exporter", "error", err)
		return nil, err
	}

	res := newResourceInternal(ctxInfo.HostID)
	provider := newInternalMeterProvider(res, &exporter, metrics.Interval)
	meter := provider.Meter("obi_internal")
	tracerFlushes, err := meter.Float64Histogram(
		attr.VendorPrefix+".ebpf.tracer.flushes",
		instrument.WithDescription("Length of the groups of traces flushed from the eBPF tracer to the next pipeline stage"),
		instrument.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	otelMetricExports, err := meter.Float64Counter(
		attr.VendorPrefix+".otel.metric.exports",
		instrument.WithDescription("Length of the metric batches submitted to the remote OTEL collector"),
	)
	if err != nil {
		return nil, err
	}

	otelMetricExportErrs, err := meter.Float64Counter(
		attr.VendorPrefix+".otel.metric.export.errors",
		instrument.WithDescription("Error count on each failed OTEL metric export"),
	)
	if err != nil {
		return nil, err
	}

	otelTraceExports, err := meter.Float64Counter(
		attr.VendorPrefix+".otel.trace.exports",
		instrument.WithDescription("Length of the trace batches submitted to the remote OTEL collector"),
	)
	if err != nil {
		return nil, err
	}

	otelTraceExportErrs, err := meter.Float64Counter(
		attr.VendorPrefix+".otel.trace.export.errors",
		instrument.WithDescription("Error count on each failed OTEL trace export"),
	)
	if err != nil {
		return nil, err
	}

	instrumentedProcesses, err := meter.Int64UpDownCounter(
		attr.VendorPrefix+".instrumented.processes",
		instrument.WithDescription("Instrumented processes by Beyla"),
	)
	if err != nil {
		return nil, err
	}

	beylaInfo, err := meter.Int64Gauge(
		attr.VendorPrefix+".internal.build.info",
		instrument.WithDescription("A metric with a constant '1' value labeled by version, revision, branch, goversion from which Beyla was built, the goos and goarch for the build."),
	)
	if err != nil {
		return nil, err
	}

	return &InternalMetricsReporter{
		ctx:                   ctx,
		tracerFlushes:         tracerFlushes,
		otelMetricExports:     otelMetricExports,
		otelMetricExportErrs:  otelMetricExportErrs,
		otelTraceExports:      otelTraceExports,
		otelTraceExportErrs:   otelTraceExportErrs,
		instrumentedProcesses: instrumentedProcesses,
		beylaInfo:             beylaInfo,
	}, nil
}

func newInternalMeterProvider(res *resource.Resource, exporter *metric.Exporter, interval time.Duration) *metric.MeterProvider {
	return metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(*exporter, metric.WithInterval(interval))),
	)
}

func (p *InternalMetricsReporter) Start(ctx context.Context) {
	p.beylaInfo.Record(ctx, 1, instrument.WithAttributes(attribute.String("goarch", runtime.GOARCH), attribute.String("goos", runtime.GOOS), attribute.String("goversion", runtime.Version()), attribute.String("version", buildinfo.Version), attribute.String("revision", buildinfo.Revision)))
}

func (p *InternalMetricsReporter) TracerFlush(length int) {
	p.tracerFlushes.Record(p.ctx, float64(length))
}

func (p *InternalMetricsReporter) OTELMetricExport(length int) {
	p.otelMetricExports.Add(p.ctx, float64(length))
}

func (p *InternalMetricsReporter) OTELMetricExportError(err error) {
	p.otelMetricExportErrs.Add(p.ctx, 1, instrument.WithAttributes(attribute.String("error", err.Error())))
}

func (p *InternalMetricsReporter) OTELTraceExport(length int) {
	p.otelTraceExports.Add(p.ctx, float64(length))
}

func (p *InternalMetricsReporter) OTELTraceExportError(err error) {
	p.otelTraceExportErrs.Add(p.ctx, 1, instrument.WithAttributes(attribute.String("error", err.Error())))
}

func (p *InternalMetricsReporter) PrometheusRequest(_, _ string) {
}

func (p *InternalMetricsReporter) InstrumentProcess(processName string) {
	p.instrumentedProcesses.Add(p.ctx, 1, instrument.WithAttributes(attribute.String("process_name", processName)))
}

func (p *InternalMetricsReporter) UninstrumentProcess(processName string) {
	p.instrumentedProcesses.Add(p.ctx, -1, instrument.WithAttributes(attribute.String("process_name", processName)))
}
