package sockets

import (
	"errors"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func configureUDP(conn net.Conn) error {
	provider, ok := conn.(syscall.Conn)
	if !ok {
		return nil
	} // in-memory dialers used by callers/tests
	raw, err := provider.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		// Go disables UDP ICMP port-unreachable reporting by default. Reenable
		// it after dialing, before the one datagram is sent on this socket.
		enabled, returned := uint32(1), uint32(0)
		optionErr = syscall.WSAIoctl(syscall.Handle(fd), syscall.SIO_UDP_CONNRESET, (*byte)(unsafe.Pointer(&enabled)), uint32(unsafe.Sizeof(enabled)), nil, 0, &returned, nil, 0)
	}); err != nil {
		return err
	}
	return optionErr
}

func udpPortUnreachable(err error) bool {
	return errors.Is(err, refusedCode) || errors.Is(err, resetCode)
}
func udpMessageTooLarge(err error) bool { return errors.Is(err, windows.WSAEMSGSIZE) }
