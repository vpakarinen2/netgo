package sockets

import (
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	refusedCode     = syscall.Errno(windows.WSAECONNREFUSED)
	netUnreachCode  = syscall.Errno(windows.WSAENETUNREACH)
	hostUnreachCode = syscall.Errno(windows.WSAEHOSTUNREACH)
	resetCode       = syscall.Errno(windows.WSAECONNRESET)
)
