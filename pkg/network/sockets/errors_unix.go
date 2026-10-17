//go:build !windows

package sockets

import "syscall"

const (
	refusedCode     = syscall.ECONNREFUSED
	netUnreachCode  = syscall.ENETUNREACH
	hostUnreachCode = syscall.EHOSTUNREACH
	resetCode       = syscall.ECONNRESET
)
