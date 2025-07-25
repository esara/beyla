package appolly

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/obi/pkg/components/connector"
	"go.opentelemetry.io/obi/pkg/components/discover"
	"go.opentelemetry.io/obi/pkg/components/ebpf"
	"go.opentelemetry.io/obi/pkg/components/exec"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/export/otel"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

func TestProcessEventsLoopDoesntBlock(t *testing.T) {
	instr, err := New(
		context.Background(),
		&global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		&beyla.Config{
			ChannelBufferLen: 1,
			Traces: otel.TracesConfig{
				TracesEndpoint: "http://something",
			},
		},
	)

	events := make(chan discover.Event[*ebpf.Instrumentable])

	go instr.instrumentedEventLoop(context.Background(), events)

	for i := 0; i < 100; i++ {
		events <- discover.Event[*ebpf.Instrumentable]{
			Obj:  &ebpf.Instrumentable{FileInfo: &exec.FileInfo{Pid: int32(i)}},
			Type: discover.EventCreated,
		}
	}

	assert.NoError(t, err)
}
