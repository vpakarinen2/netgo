package sockets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
)

const maxIgnoredUDPReplies = 64

// UDP uses a fresh connected socket per attempt. The kernel restricts replies
// to the selected remote endpoint; protocol probes also match transaction data.
type UDP struct {
	Timeout  time.Duration
	Kind     string
	MaxBytes int
	Dialer   Dialer
}

func (u *UDP) Probe(ctx context.Context, target model.Target) (result model.Result, probeErr error) {
	if err := target.Validate(); err != nil {
		return result, err
	}
	if target.Transport != model.UDP || u.Timeout <= 0 || u.MaxBytes < 48 || u.MaxBytes > 65535 {
		return result, fmt.Errorf("invalid UDP target, timeout, or byte limit")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	payload, err := makeUDPPayload(u.Kind, target.Port)
	if err != nil {
		return result, err
	}
	started := time.Now()
	result = model.Result{Target: target, Method: model.UDPProbe, Attempts: 1, UDP: &model.UDPInfo{Probe: payload.kind}}
	defer func() {
		result.Duration, result.ObservedAt = time.Since(started), time.Now().UTC()
		if ctx.Err() != nil {
			result, probeErr = model.Result{}, ctx.Err()
		}
	}()
	attemptCtx, cancel := context.WithTimeout(ctx, u.Timeout)
	defer cancel()
	dialer := u.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	network := "udp6"
	if target.Address.Is4() {
		network = "udp4"
	}
	conn, err := dialer.DialContext(attemptCtx, network, netip.AddrPortFrom(target.Address, target.Port).String())
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return u.failed(attemptCtx, result, err, false)
	}
	if conn == nil {
		return result, fmt.Errorf("UDP dialer returned no connection")
	}
	defer conn.Close()
	if err := configureUDP(conn); err != nil {
		return result, fmt.Errorf("configure UDP error reporting: %w", err)
	}
	deadline, _ := attemptCtx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return result, err
	}
	stop := context.AfterFunc(attemptCtx, func() { _ = conn.Close() })
	defer stop()
	n, err := conn.Write(payload.data)
	if err != nil {
		if attemptCtx.Err() != nil {
			return result, fmt.Errorf("UDP send: %w", attemptCtx.Err())
		}
		var timeout net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
			return result, fmt.Errorf("UDP send: %w", err)
		}
		return u.failed(attemptCtx, result, err, true)
	}
	if n != len(payload.data) {
		return result, io.ErrShortWrite
	}
	buffer := make([]byte, u.MaxBytes+1)
	for {
		if err := attemptCtx.Err(); err != nil {
			return u.failed(attemptCtx, result, err, true)
		}
		n, err := conn.Read(buffer)
		if attemptCtx.Err() != nil {
			return u.failed(attemptCtx, result, attemptCtx.Err(), true)
		}
		oversized := n > u.MaxBytes || udpMessageTooLarge(err)
		if err != nil && !oversized {
			return u.failed(attemptCtx, result, err, true)
		}
		if !oversized {
			matched, service := payload.match(buffer[:n])
			if matched {
				result.State, result.Reason, result.Service = model.Open, "udp_response", service
				result.UDP.ResponseBytes = n
				return result, nil
			}
		} else {
			result.UDP.OversizedResponses++
		}
		result.UDP.IgnoredResponses++
		if result.UDP.IgnoredResponses >= maxIgnoredUDPReplies {
			result.State, result.Reason = model.Unknown, "response_limit"
			return result, nil
		}
	}
}

func (u *UDP) failed(ctx context.Context, result model.Result, err error, sent bool) (model.Result, error) {
	var netError net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.As(err, &netError) && netError.Timeout() {
		if !sent {
			return result, fmt.Errorf("UDP socket setup: %w", err)
		}
		result.State, result.Reason = model.OpenFiltered, "timeout"
		return result, nil
	}
	if errors.Is(err, context.Canceled) {
		return result, err
	}
	if sent && udpPortUnreachable(err) {
		result.State, result.Reason = model.Closed, "port_unreachable"
		return result, nil
	}
	if errors.Is(err, netUnreachCode) {
		result.State, result.Reason = model.Unknown, "network_unreachable"
		return result, nil
	}
	if errors.Is(err, hostUnreachCode) {
		result.State, result.Reason = model.Unknown, "host_unreachable"
		return result, nil
	}
	return result, fmt.Errorf("UDP socket: %w", err)
}
