// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package aggregate

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/otel/metric/components/exemplar"
)

// now is used to return the current local time while allowing tests to
// override the default time.Now function.
var now = time.Now

// Measure receives measurements to be aggregated.
type Measure[N int64 | float64] func(context.Context, N, attribute.Set)

// Remove receives a time series to be deleted.
type Remove func(context.Context, attribute.Set)

// ComputeAggregation stores the aggregate of measurements into dest and
// returns the number of aggregate data-points output.
type ComputeAggregation func(dest *sdkmetricdata.Aggregation) int

// Builder builds an aggregate function.
type Builder[N int64 | float64] struct {
	// Temporality is the temporality used for the returned aggregate function.
	//
	// If this is not provided a default of cumulative will be used (except for
	// the last-value aggregate function where delta is the only appropriate
	// temporality).
	Temporality sdkmetricdata.Temporality
	// Filter is the attribute filter the aggregate function will use on the
	// input of measurements.
	Filter attribute.Filter
	// ReservoirFunc is the factory function used by aggregate functions to
	// create new exemplar reservoirs for a new seen attribute set.
	//
	// If this is not provided a default factory function that returns an
	// exemplar.Drop reservoir will be used.
	ReservoirFunc func() exemplar.FilteredReservoir[N]
	// AggregationLimit is the cardinality limit of measurement attributes. Any
	// measurement for new attributes once the limit has been reached will be
	// aggregated into a single aggregate for the "otel.metric.overflow"
	// attribute.
	//
	// If AggregationLimit is less than or equal to zero there will not be an
	// aggregation limit imposed (i.e. unlimited attribute sets).
	AggregationLimit int
}

func (b Builder[N]) resFunc() func() exemplar.FilteredReservoir[N] {
	if b.ReservoirFunc != nil {
		return b.ReservoirFunc
	}

	return exemplar.Drop
}

type fltrMeasure[N int64 | float64] func(ctx context.Context, value N, fltrAttr attribute.Set, droppedAttr []attribute.KeyValue)

func (b Builder[N]) filter(f fltrMeasure[N]) Measure[N] {
	if b.Filter != nil {
		fltr := b.Filter // Copy to make it immutable after assignment.
		return func(ctx context.Context, n N, a attribute.Set) {
			fAttr, dropped := a.Filter(fltr)
			f(ctx, n, fAttr, dropped)
		}
	}
	return func(ctx context.Context, n N, a attribute.Set) {
		f(ctx, n, a, nil)
	}
}

// LastValue returns a last-value aggregate function input and output.
func (b Builder[N]) LastValue() (Measure[N], Remove, ComputeAggregation) {
	lv := newLastValue[N](b.AggregationLimit, b.resFunc())
	switch b.Temporality {
	case sdkmetricdata.DeltaTemporality:
		return b.filter(lv.measure), lv.remove, lv.delta
	default:
		return b.filter(lv.measure), lv.remove, lv.cumulative
	}
}

// PrecomputedLastValue returns a last-value aggregate function input and
// output. The aggregation returned from the returned ComputeAggregation
// function will always only return values from the previous collection cycle.
func (b Builder[N]) PrecomputedLastValue() (Measure[N], Remove, ComputeAggregation) {
	lv := newPrecomputedLastValue[N](b.AggregationLimit, b.resFunc())
	switch b.Temporality {
	case sdkmetricdata.DeltaTemporality:
		return b.filter(lv.measure), lv.remove, lv.delta
	default:
		return b.filter(lv.measure), lv.remove, lv.cumulative
	}
}

// PrecomputedSum returns a sum aggregate function input and output. The
// arguments passed to the input are expected to be the precomputed sum values.
func (b Builder[N]) PrecomputedSum(monotonic bool) (Measure[N], Remove, ComputeAggregation) {
	s := newPrecomputedSum[N](monotonic, b.AggregationLimit, b.resFunc())
	switch b.Temporality {
	case sdkmetricdata.DeltaTemporality:
		return b.filter(s.measure), s.remove, s.delta
	default:
		return b.filter(s.measure), s.remove, s.cumulative
	}
}

// Sum returns a sum aggregate function input and output.
func (b Builder[N]) Sum(monotonic bool) (Measure[N], Remove, ComputeAggregation) {
	s := newSum[N](monotonic, b.AggregationLimit, b.resFunc())
	switch b.Temporality {
	case sdkmetricdata.DeltaTemporality:
		return b.filter(s.measure), s.remove, s.delta
	default:
		return b.filter(s.measure), s.remove, s.cumulative
	}
}

// ExplicitBucketHistogram returns a histogram aggregate function input and
// output.
func (b Builder[N]) ExplicitBucketHistogram(boundaries []float64, noMinMax, noSum bool) (Measure[N], Remove, ComputeAggregation) {
	h := newHistogram[N](boundaries, noMinMax, noSum, b.AggregationLimit, b.resFunc())
	switch b.Temporality {
	case sdkmetricdata.DeltaTemporality:
		return b.filter(h.measure), h.remove, h.delta
	default:
		return b.filter(h.measure), h.remove, h.cumulative
	}
}

// ExponentialBucketHistogram returns a histogram aggregate function input and
// output.
func (b Builder[N]) ExponentialBucketHistogram(maxSize, maxScale int32, noMinMax, noSum bool) (Measure[N], Remove, ComputeAggregation) {
	h := newExponentialHistogram[N](maxSize, maxScale, noMinMax, noSum, b.AggregationLimit, b.resFunc())
	switch b.Temporality {
	case sdkmetricdata.DeltaTemporality:
		return b.filter(h.measure), h.remove, h.delta
	default:
		return b.filter(h.measure), h.remove, h.cumulative
	}
}

// reset ensures s has capacity and sets it length. If the capacity of s too
// small, a new slice is returned with the specified capacity and length.
func reset[T any](s []T, length, capacity int) []T {
	if cap(s) < capacity {
		return make([]T, length, capacity)
	}
	return s[:length]
}
