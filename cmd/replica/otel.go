package main

import (
	"context"
	"errors"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

func setupOTel(ctx context.Context) (shutdown func(context.Context) error, err error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("plc-replica"),
		),
	)
	if err != nil {
		return nil, err
	}

	var shutdowns []func(context.Context) error

	// Traces: OTLP HTTP exporter, only enabled if an endpoint is configured.
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != "" {
		traceExporter, err := otlptracehttp.New(ctx)
		if err != nil {
			return nil, err
		}

		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(traceExporter),
			sdktrace.WithResource(res),
		)
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		))
		shutdowns = append(shutdowns, tp.Shutdown)
	}

	// Metrics: Prometheus exporter, served via /metrics HTTP endpoint.
	promExporter, err := prometheus.New()
	if err != nil {
		return nil, err
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(promExporter),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)
	shutdowns = append(shutdowns, mp.Shutdown)

	shutdown = func(ctx context.Context) error {
		var errs []error
		for _, fn := range shutdowns {
			errs = append(errs, fn(ctx))
		}
		return errors.Join(errs...)
	}
	return shutdown, nil
}
