// Package sockets implements unprivileged socket-based network probes.
package sockets

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
)

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Connect performs a TCP handshake and closes the socket without application
// data. A nil Dialer uses net.Dialer. Instances support concurrent probes.
type Connect struct {
	Timeout time.Duration
	Dialer  Dialer
}

func (c *Connect) Probe(ctx context.Context, target model.Target) (model.Result, error) {
	if err := target.Validate(); err != nil {
		return model.Result{}, err
	}
	if target.Transport != model.TCP || c.Timeout <= 0 {
		return model.Result{}, fmt.Errorf("TCP connect requires a TCP target and positive timeout")
	}
	if err := ctx.Err(); err != nil {
		return model.Result{}, err
	}
	dialer := c.Dialer
	if dialer == nil {
		dialer = &net.Dialer{KeepAlive: -1}
	}
	attemptCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	address := netip.AddrPortFrom(target.Address, target.Port).String()
	network := "tcp6"
	if target.Address.Is4() {
		network = "tcp4"
	}
	started := time.Now()
	conn, err := dialer.DialContext(attemptCtx, network, address)
	if conn != nil {
		// No established connection survives the attempt, including a dialer
		// returning both a connection and an error.
		_ = conn.Close()
	}
	if ctx.Err() != nil {
		return model.Result{}, ctx.Err()
	}
	result := model.Result{Target: target, Method: model.TCPConnect, ObservedAt: time.Now().UTC(), Duration: time.Since(started), Attempts: 1}
	if err == nil {
		if conn == nil {
			return model.Result{}, fmt.Errorf("dial %s: dialer returned no connection", address)
		}
		result.State, result.Reason = model.Open, "connected"
		return result, nil
	}
	var netError net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netError) && netError.Timeout()) {
		result.State, result.Reason = model.Unknown, "timeout"
		return result, nil
	}
	state, reason, recognized := classifyConnectError(err)
	if recognized {
		result.State, result.Reason = state, reason
		return result, nil
	}
	return model.Result{}, fmt.Errorf("dial %s: %w", address, err)
}
