package core

import (
	"context"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
)

// ScriptRunner returns bounded metadata without modifying the port result.
type ScriptRunner interface {
	Run(context.Context, model.Result, time.Time) []model.ScriptRun
}

func (s *state) recordScripts(runs []model.ScriptRun) {
	if s.summary.Scripts == nil {
		return
	}
	stats := s.summary.Scripts
	for _, run := range runs {
		stats.Findings += uint64(len(run.Findings))
		if run.Status != "skipped" {
			stats.Invocations++
		}
		switch run.Status {
		case "completed":
			stats.Completed++
		case "inconclusive":
			stats.Inconclusive++
		case "skipped":
			stats.Skipped++
		case "timeout":
			stats.Timeouts++
		case "canceled":
			stats.Canceled++
		default:
			stats.Errors++
		}
	}
}
