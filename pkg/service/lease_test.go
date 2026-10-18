package service

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectionLeaseReleasedOnDialFailuresAndSuccess(t *testing.T) {
	for _, mode := range []string{"dial-error", "nil-connection", "success"} {
		t.Run(mode, func(t *testing.T) {
			var held atomic.Int32
			i := newInspector(t, Options{Timeout: time.Second, MaxBytes: 256, Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
				if mode == "dial-error" {
					return nil, errors.New("fixture dial error")
				}
				if mode == "nil-connection" {
					return nil, nil
				}
				client, peer := net.Pipe()
				go func() { defer peer.Close(); _, _ = peer.Write([]byte("SSH-2.0-fixture\r\n")) }()
				return client, nil
			})})
			_, info := i.Identify(context.Background(), targetFor("127.0.0.1:22"), func(context.Context) (func(), error) { held.Add(1); return func() { held.Add(-1) }, nil })
			if held.Load() != 0 {
				t.Fatal("connection budget leaked")
			}
			if mode == "success" && info.Status != "identified" {
				t.Fatalf("unexpected inspection: %+v", info)
			}
		})
	}
}
