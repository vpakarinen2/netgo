package model

import "time"

// Script findings are plugin claims with evidence references, not verified
// vulnerabilities. Identity and target association are assigned by Netgo.
type ScriptFinding struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	Severity       string   `json:"severity"`
	Message        string   `json:"message"`
	EvidenceFields []string `json:"evidence_fields"`
}

// ScriptDetail is informational output backed by collected evidence. Details do
// not contribute to finding counts or imply that a security issue was found.
type ScriptDetail struct {
	Label          string   `json:"label"`
	Value          string   `json:"value"`
	EvidenceFields []string `json:"evidence_fields"`
}

type ScriptRun struct {
	ID       string          `json:"id"`
	Version  string          `json:"version"`
	SHA256   string          `json:"sha256"`
	Status   string          `json:"status"`
	Duration time.Duration   `json:"duration_ns"`
	Reason   string          `json:"reason,omitempty"`
	Error    string          `json:"error,omitempty"`
	Stderr   string          `json:"stderr,omitempty"`
	Findings []ScriptFinding `json:"findings,omitempty"`
	Details  []ScriptDetail  `json:"details,omitempty"`
}

type ScriptSummary struct {
	Invocations  uint64 `json:"invocations"`
	Completed    uint64 `json:"completed"`
	Inconclusive uint64 `json:"inconclusive"`
	Skipped      uint64 `json:"skipped"`
	Errors       uint64 `json:"errors"`
	Timeouts     uint64 `json:"timeouts"`
	Canceled     uint64 `json:"canceled"`
	Findings     uint64 `json:"findings"`
}
