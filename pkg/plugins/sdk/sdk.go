// Package sdk is the netgo.script/v1 JSON contract. It has no runtime dependency
// on wazero and can be compiled with standard Go for wasip1/wasm.
package sdk

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/vpakarinen2/netgo/internal/jsonwire"
	"github.com/vpakarinen2/netgo/pkg/model"
)

const APIVersion = "netgo.script/v1"
const MaxInput = 512 * 1024
const MaxOutput = 64 * 1024
const MaxFindings = 16
const MaxDetails = 128

type Request struct {
	APIVersion     string                     `json:"api_version"`
	EvaluationTime time.Time                  `json:"evaluation_time"`
	Parameters     map[string]json.RawMessage `json:"parameters"`
	Result         model.Result               `json:"result"`
}

type Response struct {
	APIVersion string                `json:"api_version"`
	Outcome    string                `json:"outcome"`
	Reason     string                `json:"reason,omitempty"`
	Findings   []model.ScriptFinding `json:"findings"`
	Details    []model.ScriptDetail  `json:"details,omitempty"`
}

func ReadRequest(reader io.Reader) (Request, error) {
	var request Request
	data, err := io.ReadAll(io.LimitReader(reader, MaxInput+1))
	if err != nil {
		return request, err
	}
	if len(data) > MaxInput {
		return request, fmt.Errorf("input exceeds %d bytes", MaxInput)
	}
	if err := jsonwire.Decode(data, &request); err != nil {
		return request, err
	}
	if request.APIVersion != APIVersion || request.EvaluationTime.IsZero() {
		return request, fmt.Errorf("invalid request API version or evaluation time")
	}
	if err := request.Result.Target.Validate(); err != nil {
		return request, err
	}
	if request.Result.Target.Transport != model.TCP || request.Result.State != model.Open || len(request.Result.Scripts) != 0 {
		return request, fmt.Errorf("request must contain an open TCP result without scripts")
	}
	return request, nil
}

func (r Request) Int(name string) (int64, error) {
	var value int64
	err := json.Unmarshal(r.Parameters[name], &value)
	return value, err
}

func (r Request) String(name string) (string, error) {
	var value string
	err := json.Unmarshal(r.Parameters[name], &value)
	return value, err
}

func (r Request) Bool(name string) (bool, error) {
	var value bool
	err := json.Unmarshal(r.Parameters[name], &value)
	return value, err
}

// Main runs a single command invocation. Only protocol JSON goes to stdout.
func Main(check func(Request) (Response, error)) {
	request, err := ReadRequest(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	response, err := check(request)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	response.APIVersion = APIVersion
	data, err := json.Marshal(response)
	if err != nil || len(data) > MaxOutput {
		fmt.Fprintln(os.Stderr, "response cannot be encoded within output limit")
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
		os.Exit(1)
	}
}
