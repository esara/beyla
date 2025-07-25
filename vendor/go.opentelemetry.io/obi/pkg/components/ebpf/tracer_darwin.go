// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"context"
	"time"

	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/app/request"
	ebpfcommon "go.opentelemetry.io/obi/pkg/components/ebpf/common"
	"go.opentelemetry.io/obi/pkg/components/exec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type instrumenter struct{}

// dummy implementations to avoid compilation errors in Darwin.
// The tracer component is only usable in Linux.

func (pt *ProcessTracer) Run(_ context.Context, _ *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
}

func NewProcessTracer(_ ProcessTracerType, _ []Tracer, _ time.Duration) *ProcessTracer {
	return nil
}

func (pt *ProcessTracer) Init(_ *ebpfcommon.EBPFEventContext) error {
	pt.log.Debug("avoiding linter complaints for not using log and shutdownTimeout fields",
		"v", pt.shutdownTimeout)
	return nil
}

func (pt *ProcessTracer) NewExecutable(_ *link.Executable, _ *Instrumentable) error {
	return nil
}

func (pt *ProcessTracer) NewExecutableInstance(_ *Instrumentable) error {
	return nil
}

func (pt *ProcessTracer) UnlinkExecutable(_ *exec.FileInfo) {}

func RunUtilityTracer(_ context.Context, _ *ebpfcommon.EBPFEventContext, _ UtilityTracer) error {
	return nil
}
