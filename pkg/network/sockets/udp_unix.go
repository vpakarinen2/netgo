//go:build !windows

package sockets

import (
	"errors"
	"net"
	"syscall"
)

func configureUDP(net.Conn) error       { return nil }
func udpPortUnreachable(err error) bool { return errors.Is(err, refusedCode) }
func udpMessageTooLarge(err error) bool { return errors.Is(err, syscall.EMSGSIZE) }
