// Package output defines the result sink used by the scan dispatcher.
package output

import (
	"context"

	"github.com/vpakarinen2/netgo/pkg/model"
)

// Writer receives results serially from a single output coordinator. Close must
// flush owned buffers without closing process stdout or stderr. Write and Close
// errors are propagated to the caller; results must not be silently dropped.
type Writer interface {
	WriteResult(context.Context, model.Result) error
	WriteSummary(context.Context, model.Summary) error
	Close() error
}
