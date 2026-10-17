package core

import (
	"context"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/network"
)

// Identifier honors cancellation and returns best-effort metadata. It must use
// gate before every additional connection. Identification failures are not port
// failures, and must not change the port scan's target/state/reason/timing.
type Identifier interface {
	Identify(context.Context, model.Target, network.ConnectionGate) (*model.Service, model.Identification)
}
