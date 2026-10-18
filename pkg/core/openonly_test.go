package core

import (
	"context"
	"testing"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func TestOpenOnlyFiltersRowsButPreservesCounts(t *testing.T) {
	states := []model.PortState{model.Open, model.Closed, model.Unknown, model.OpenFiltered, model.Filtered}
	for _, transport := range []model.Transport{model.TCP, model.UDP} {
		for _, only := range []bool{false, true} {
			options := testOptions()
			options.Transport = transport
			options.OpenOnly = only
			options.Diagnostics = true
			prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
				result := openResult(target)
				result.State = states[target.Port-1]
				return result, nil
			})
			writer := &recordingWriter{}
			summary, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{1, 2, 3, 4, 5}, options, prober, writer)
			wantRows := 5
			if only {
				wantRows = 1
			}
			if err != nil || len(writer.results) != wantRows || summary.Reported != uint64(wantRows) || summary.OpenOnly != only || summary.Completed != 5 || summary.Total != 5 || summary.Attempts != 5 || summary.Open != 1 || summary.Closed != 1 || summary.Unknown != 1 || summary.OpenFiltered != 1 || summary.Filtered != 1 {
				t.Fatalf("transport=%s only=%v rows=%d summary=%+v err=%v", transport, only, len(writer.results), summary, err)
			}
			if summary.Diagnostics.PortAttempts != 5 {
				t.Fatal("filter changed diagnostic attempts")
			}
			if only && writer.results[0].State != model.Open {
				t.Fatal("uncertain result passed open-only filter")
			}
		}
	}
}

func TestOpenOnlyNoOpenPortsStillCompletes(t *testing.T) {
	options := testOptions()
	options.OpenOnly = true
	writer := &recordingWriter{}
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
		result := openResult(target)
		result.State = model.Closed
		return result, nil
	})
	summary, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{22, 80}, options, prober, writer)
	if err != nil || len(writer.results) != 0 || summary.Completed != 2 || summary.Closed != 2 || summary.Reported != 0 || !writer.closed || writer.summary.Status != "completed" {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
}
