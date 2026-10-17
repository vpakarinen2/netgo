package sockets

import (
	"errors"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func classifyConnectError(err error) (model.PortState, string, bool) {
	switch {
	case errors.Is(err, refusedCode):
		return model.Closed, "connection_refused", true
	case errors.Is(err, netUnreachCode):
		return model.Unknown, "network_unreachable", true
	case errors.Is(err, hostUnreachCode):
		return model.Unknown, "host_unreachable", true
	case errors.Is(err, resetCode):
		return model.Unknown, "connection_reset", true
	default:
		return "", "", false
	}
}
