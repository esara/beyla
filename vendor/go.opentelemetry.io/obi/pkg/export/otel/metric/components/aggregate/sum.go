// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package aggregate

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/otel/metric/components/exemplar"
)

type sumValue[N int64 | float64] struct {
	n     N
	res   exemplar.FilteredReservoir[N]
	attrs attribute.Set
}

// valueMap is the storage for sums.
type valueMap[N int64 | float64] struct {
	sync.Mutex
	newRes func() exemplar.FilteredReservoir[N]
	limit  limiter[sumValue[N]]
	values map[attribute.Distinct]sumValue[N]
}

func newValueMap[N int64 | float64](limit int, r func() exemplar.FilteredReservoir[N]) *valueMap[N] {
	return &valueMap[N]{
		newRes: r,
		limit:  newLimiter[sumValue[N]](limit),
		values: make(map[attribute.Distinct]sumValue[N]),
	}
}

func (s *valueMap[N]) measure(ctx context.Context, value N, fltrAttr attribute.Set, droppedAttr []attribute.KeyValue) {
	s.Lock()
	defer s.Unlock()

	attr := s.limit.Attributes(fltrAttr, s.values)
	v, ok := s.values[attr.Equivalent()]
	if !ok {
		v.res = s.newRes()
	}

	v.attrs = attr
	v.n += value
	v.res.Offer(ctx, value, droppedAttr)

	s.values[attr.Equivalent()] = v
}

func (s *valueMap[N]) remove(_ context.Context, fltrAttr attribute.Set) {
	s.Lock()
	defer s.Unlock()

	key := fltrAttr.Equivalent()

	delete(s.values, key)
}

// newSum returns an aggregator that summarizes a set of measurements as their
// arithmetic sum. Each sum is scoped by attributes and the aggregation cycle
// the measurements were made in.
func newSum[N int64 | float64](monotonic bool, limit int, r func() exemplar.FilteredReservoir[N]) *sum[N] {
	return &sum[N]{
		valueMap:  newValueMap[N](limit, r),
		monotonic: monotonic,
		start:     now(),
	}
}

// sum summarizes a set of measurements made as their arithmetic sum.
type sum[N int64 | float64] struct {
	*valueMap[N]

	monotonic bool
	start     time.Time
}

func (s *sum[N]) delta(dest *sdkmetricdata.Aggregation) int {
	t := now()

	// If *dest is not a metricdata.Sum, memory reuse is missed. In that case,
	// use the zero-value sData and hope for better alignment next cycle.
	sData, _ := (*dest).(sdkmetricdata.Sum[N])
	sData.Temporality = sdkmetricdata.DeltaTemporality
	sData.IsMonotonic = s.monotonic

	s.Lock()
	defer s.Unlock()

	n := len(s.values)
	dPts := reset(sData.DataPoints, n, n)

	var i int
	for _, val := range s.values {
		dPts[i].Attributes = val.attrs
		dPts[i].StartTime = s.start
		dPts[i].Time = t
		dPts[i].Value = val.n
		collectExemplars(&dPts[i].Exemplars, val.res.Collect)
		i++
	}
	clear(s.values)
	// The delta collection cycle resets.
	s.start = t

	sData.DataPoints = dPts
	*dest = sData

	return n
}

func (s *sum[N]) cumulative(dest *sdkmetricdata.Aggregation) int {
	t := now()

	// If *dest is not a metricdata.Sum, memory reuse is missed. In that case,
	// use the zero-value sData and hope for better alignment next cycle.
	sData, _ := (*dest).(sdkmetricdata.Sum[N])
	sData.Temporality = sdkmetricdata.CumulativeTemporality
	sData.IsMonotonic = s.monotonic

	s.Lock()
	defer s.Unlock()

	n := len(s.values)
	dPts := reset(sData.DataPoints, n, n)

	var i int
	for _, value := range s.values {
		dPts[i].Attributes = value.attrs
		dPts[i].StartTime = s.start
		dPts[i].Time = t
		dPts[i].Value = value.n
		collectExemplars(&dPts[i].Exemplars, value.res.Collect)
		// TODO (#3006): This will use an unbounded amount of memory if there
		// are unbounded number of attribute sets being aggregated. Attribute
		// sets that become "stale" need to be forgotten so this will not
		// overload the system.
		i++
	}

	sData.DataPoints = dPts
	*dest = sData

	return n
}

// newPrecomputedSum returns an aggregator that summarizes a set of
// observatrions as their arithmetic sum. Each sum is scoped by attributes and
// the aggregation cycle the measurements were made in.
func newPrecomputedSum[N int64 | float64](monotonic bool, limit int, r func() exemplar.FilteredReservoir[N]) *precomputedSum[N] {
	return &precomputedSum[N]{
		valueMap:  newValueMap[N](limit, r),
		monotonic: monotonic,
		start:     now(),
	}
}

// precomputedSum summarizes a set of observatrions as their arithmetic sum.
type precomputedSum[N int64 | float64] struct {
	*valueMap[N]

	monotonic bool
	start     time.Time

	reported map[attribute.Distinct]N
}

func (s *precomputedSum[N]) delta(dest *sdkmetricdata.Aggregation) int {
	t := now()
	newReported := make(map[attribute.Distinct]N)

	// If *dest is not a metricdata.Sum, memory reuse is missed. In that case,
	// use the zero-value sData and hope for better alignment next cycle.
	sData, _ := (*dest).(sdkmetricdata.Sum[N])
	sData.Temporality = sdkmetricdata.DeltaTemporality
	sData.IsMonotonic = s.monotonic

	s.Lock()
	defer s.Unlock()

	n := len(s.values)
	dPts := reset(sData.DataPoints, n, n)

	var i int
	for key, value := range s.values {
		delta := value.n - s.reported[key]

		dPts[i].Attributes = value.attrs
		dPts[i].StartTime = s.start
		dPts[i].Time = t
		dPts[i].Value = delta
		collectExemplars(&dPts[i].Exemplars, value.res.Collect)

		newReported[key] = value.n
		i++
	}
	// Unused attribute sets do not report.
	clear(s.values)
	s.reported = newReported
	// The delta collection cycle resets.
	s.start = t

	sData.DataPoints = dPts
	*dest = sData

	return n
}

func (s *precomputedSum[N]) cumulative(dest *sdkmetricdata.Aggregation) int {
	t := now()

	// If *dest is not a metricdata.Sum, memory reuse is missed. In that case,
	// use the zero-value sData and hope for better alignment next cycle.
	sData, _ := (*dest).(sdkmetricdata.Sum[N])
	sData.Temporality = sdkmetricdata.CumulativeTemporality
	sData.IsMonotonic = s.monotonic

	s.Lock()
	defer s.Unlock()

	n := len(s.values)
	dPts := reset(sData.DataPoints, n, n)

	var i int
	for _, val := range s.values {
		dPts[i].Attributes = val.attrs
		dPts[i].StartTime = s.start
		dPts[i].Time = t
		dPts[i].Value = val.n
		collectExemplars(&dPts[i].Exemplars, val.res.Collect)

		i++
	}

	// Unused attribute sets do not report.
	clear(s.values)

	sData.DataPoints = dPts
	*dest = sData

	return n
}
