// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package aggregate

import (
	"sync"

	sdkmetricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/otel/metric/components/exemplar"
)

var exemplarPool = sync.Pool{
	New: func() any { return new([]exemplar.Exemplar) },
}

func collectExemplars[N int64 | float64](out *[]sdkmetricdata.Exemplar[N], f func(*[]exemplar.Exemplar)) {
	dest := exemplarPool.Get().(*[]exemplar.Exemplar)
	defer func() {
		*dest = (*dest)[:0]
		exemplarPool.Put(dest)
	}()

	*dest = reset(*dest, len(*out), cap(*out))

	f(dest)

	*out = reset(*out, len(*dest), cap(*dest))
	for i, e := range *dest {
		(*out)[i].FilteredAttributes = e.FilteredAttributes
		(*out)[i].Time = e.Time
		(*out)[i].SpanID = e.SpanID
		(*out)[i].TraceID = e.TraceID

		switch e.Value.Type() {
		case exemplar.Int64ValueType:
			(*out)[i].Value = N(e.Value.Int64())
		case exemplar.Float64ValueType:
			(*out)[i].Value = N(e.Value.Float64())
		}
	}
}
