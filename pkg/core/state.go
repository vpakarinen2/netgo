// Package core coordinates bounded target production, probes, and results.
package core

import (
	"sync/atomic"

	"github.com/vpakarinen2/netgo/pkg/model"
)

// state has one result-coordinator owner. Only attempts is updated by workers.
type state struct {
	attempts atomic.Uint64
	summary  model.Summary
}

func (s *state) record(result model.Result) {
	s.summary.Completed++
	switch result.State {
	case model.Open:
		s.summary.Open++
	case model.Closed:
		s.summary.Closed++
	case model.OpenFiltered:
		s.summary.OpenFiltered++
	case model.Filtered:
		s.summary.Filtered++
	default:
		s.summary.Unknown++
	}
}

func (s *state) progress() model.Progress {
	return model.Progress{Completed: s.summary.Completed, Total: s.summary.Total, Attempts: s.attempts.Load(), Open: s.summary.Open, Closed: s.summary.Closed, OpenFiltered: s.summary.OpenFiltered, Filtered: s.summary.Filtered, Unknown: s.summary.Unknown}
}
