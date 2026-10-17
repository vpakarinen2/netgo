// Package network defines the contract between scheduling and network backends.
package network

import (
	"context"
	"net"

	"github.com/vpakarinen2/netgo/pkg/model"
)

// Dialer and ConnectionGate let identification share the scanner's connection
// budget without coupling protocol code to its scheduler.
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type ConnectionGate func(context.Context) error

// Prober performs one attempt. Implementations must support concurrent calls,
// honor cancellation, and release per-attempt resources before returning.
// Network observations (including refusal or silence) are results; local
// failures and cancellation are errors. Retry policy belongs to the dispatcher.
type Prober interface {
	Probe(context.Context, model.Target) (model.Result, error)
}
