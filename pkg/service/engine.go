package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/network"
	"github.com/vpakarinen2/netgo/pkg/network/targets"
)

type Options struct {
	Timeout    time.Duration
	MaxBytes   int
	Active     bool
	ServerName string
	Dialer     network.Dialer
}

type Inspector struct {
	options       Options
	fingerprinter *Fingerprinter
}

func New(options Options) (*Inspector, error) {
	if options.Timeout <= 0 || options.Timeout > time.Minute || options.MaxBytes < 256 || options.MaxBytes > MaxBytes {
		return nil, fmt.Errorf("invalid service timeout or byte limit")
	}
	if options.ServerName != "" && !ValidServerName(options.ServerName) {
		return nil, fmt.Errorf("service server name must be an ASCII DNS hostname")
	}
	options.ServerName = strings.TrimSuffix(strings.ToLower(options.ServerName), ".")
	f, err := NewFingerprinter()
	if err != nil {
		return nil, err
	}
	return &Inspector{options: options, fingerprinter: f}, nil
}

func ValidServerName(name string) bool {
	if !targets.ValidHostname(name) {
		return false
	}
	_, err := netip.ParseAddr(strings.TrimSuffix(name, "."))
	return err != nil
}

// Identify performs at most three additional connections: passive banner,
// TLS (optionally HTTP on that connection), then plaintext HTTP if TLS failed.
// gate is called before each dial. Inspection failures are metadata, never
// replacements for the original port observation. Instances are concurrent-safe.
func (i *Inspector) Identify(ctx context.Context, target model.Target, gate network.ConnectionGate) (service *model.Service, info model.Identification) {
	started := time.Now()
	info.Status = "unrecognized"
	defer func() {
		info.Duration = time.Since(started)
		if ctx.Err() != nil {
			info.Status, info.Error = "canceled", ctx.Err().Error()
		}
	}()
	if err := target.Validate(); err != nil {
		info.Status, info.Error = "failed", err.Error()
		return
	}
	if target.Transport != model.TCP || (target.Hostname != "" && !ValidServerName(target.Hostname)) {
		info.Status, info.Error = "failed", "invalid TCP inspection target"
		return
	}
	target.Hostname = strings.TrimSuffix(strings.ToLower(target.Hostname), ".")
	if err := ctx.Err(); err != nil {
		return
	}
	inspectCtx, cancel := context.WithTimeout(ctx, i.options.Timeout)
	defer cancel()
	conn, release, err := i.dial(inspectCtx, target, gate, &info)
	if err != nil {
		setFailure(&info, err)
		return
	}
	window := min(200*time.Millisecond, i.options.Timeout/4)
	if deadline, ok := inspectCtx.Deadline(); ok {
		if err := conn.SetReadDeadline(minTime(deadline, time.Now().Add(window))); err != nil {
			release()
			setFailure(&info, err)
			return
		}
	}
	data, readErr := readAhead(conn, i.options.MaxBytes)
	release()
	info.ReadLimitReached = len(data) == i.options.MaxBytes
	if len(data) != 0 {
		service = i.fingerprinter.Match(data)
		if service != nil {
			info.Status = "identified"
		} else {
			info.Evidence = []model.Evidence{evidence("banner", data)}
		}
		return
	}
	if inspectCtx.Err() != nil {
		setFailure(&info, inspectCtx.Err())
		return
	}
	if !i.options.Active {
		setFailure(&info, readErr)
		if errors.Is(readErr, io.EOF) {
			info.Status, info.Error = "unrecognized", ""
		}
		return
	}
	if inspectCtx.Err() != nil {
		setFailure(&info, inspectCtx.Err())
		return
	}
	tlsCtx, stopTLS := context.WithTimeout(inspectCtx, min(time.Second, i.options.Timeout/3))
	service, err = i.inspectTLS(tlsCtx, target, gate, &info)
	stopTLS()
	if service != nil {
		info.Status = "identified"
		if err != nil {
			info.Error = clipped(err.Error(), 512)
		}
		return
	}
	if inspectCtx.Err() != nil {
		setFailure(&info, inspectCtx.Err())
		return
	}
	httpCtx, stopHTTP := context.WithTimeout(inspectCtx, min(time.Second, i.options.Timeout/3))
	defer stopHTTP()
	conn, release, err = i.dial(httpCtx, target, gate, &info)
	if err != nil {
		setFailure(&info, err)
		return
	}
	defer release()
	data, err = i.httpProbe(conn, target)
	info.ReadLimitReached = info.ReadLimitReached || len(data) == i.options.MaxBytes
	if service = i.fingerprinter.Match(data); service != nil {
		info.Status = "identified"
		return
	}
	if len(data) != 0 {
		info.Evidence = []model.Evidence{evidence("response", data)}
	}
	if err != nil {
		setFailure(&info, err)
	}
	return
}

func (i *Inspector) dial(ctx context.Context, target model.Target, gate network.ConnectionGate, info *model.Identification) (net.Conn, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	budgetRelease := func() {}
	if gate != nil {
		var err error
		budgetRelease, err = gate(ctx)
		if err != nil {
			return nil, nil, err
		}
	}
	owned := false
	defer func() {
		if !owned {
			budgetRelease()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	dialer := i.options.Dialer
	if dialer == nil {
		dialer = &net.Dialer{KeepAlive: -1}
	}
	info.Connections++
	network := "tcp6"
	if target.Address.Is4() {
		network = "tcp4"
	}
	conn, err := dialer.DialContext(ctx, network, netip.AddrPortFrom(target.Address, target.Port).String())
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, nil, err
	}
	if conn == nil {
		return nil, nil, fmt.Errorf("service dialer returned no connection")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	owned = true
	var once sync.Once
	return conn, func() { once.Do(func() { stop(); _ = conn.Close(); budgetRelease() }) }, nil
}

func (i *Inspector) httpProbe(conn net.Conn, target model.Target) ([]byte, error) {
	host := i.httpAuthority(target)
	request := "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: netgo\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		return nil, err
	}
	return readAhead(conn, i.options.MaxBytes)
}

func (i *Inspector) httpAuthority(target model.Target) string {
	host := i.options.ServerName
	if host == "" {
		host = target.Hostname
	}
	if host == "" {
		host = target.Address.String()
	}
	return net.JoinHostPort(host, fmt.Sprint(target.Port))
}

func setFailure(info *model.Identification, err error) {
	if err == nil {
		return
	}
	info.Status = "failed"
	var netError net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netError) && netError.Timeout() {
		info.Status = "timeout"
	}
	if errors.Is(err, context.Canceled) {
		info.Status = "canceled"
	}
	info.Error = clipped(err.Error(), 512)
}

func clipped(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return strings.ToValidUTF8(value[:limit], "?")
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
