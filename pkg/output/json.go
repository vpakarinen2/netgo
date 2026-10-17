package output

import (
	"context"
	"encoding/json"
	"io"

	"github.com/vpakarinen2/netgo/pkg/model"
)

const SchemaVersion = 1

// Event is one NDJSON line. Exactly one of Result and Summary is present.
type Event struct {
	SchemaVersion int            `json:"schema_version"`
	Type          string         `json:"type"`
	Result        *model.Result  `json:"result,omitempty"`
	Summary       *model.Summary `json:"summary,omitempty"`
}

type JSON struct{ encoder *json.Encoder }

func NewJSON(writer io.Writer) *JSON { return &JSON{encoder: json.NewEncoder(writer)} }

func (j *JSON) WriteResult(ctx context.Context, result model.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return j.encoder.Encode(Event{SchemaVersion: SchemaVersion, Type: "result", Result: &result})
}

func (j *JSON) WriteSummary(ctx context.Context, summary model.Summary) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return j.encoder.Encode(Event{SchemaVersion: SchemaVersion, Type: "summary", Summary: &summary})
}

func (j *JSON) Close() error { return nil }
