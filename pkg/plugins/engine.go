package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"

	"github.com/vpakarinen2/netgo/internal/jsonwire"
	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/plugins/sdk"
)

const MaxRuns = 100000
const PortTimeout = 5 * time.Second
const MaxStderr = 8 * 1024

type Limits struct {
	Timeout   time.Duration
	MemoryMiB int
}

func (l Limits) Validate() error {
	if l.Timeout <= 0 || l.Timeout > PortTimeout || l.MemoryMiB < 16 || l.MemoryMiB > 256 {
		return fmt.Errorf("script timeout must be >0 and <=5s; memory must be 16-256 MiB")
	}
	return nil
}

type bundle struct {
	manifest   Manifest
	module     wazero.CompiledModule
	parameters map[string]json.RawMessage
	overrides  map[string]json.RawMessage
}

// Engine is safe for concurrent Run calls. Close it only after workers join.
// No guest gets host environment, files, network sockets, or process access.
type Engine struct {
	runtime wazero.Runtime
	bundles []bundle
	limits  Limits
}

func Load(ctx context.Context, paths, parameters []string, limits Limits) (*Engine, error) {
	engine, err := load(ctx, paths, parameters, limits)
	if err != nil {
		return nil, &loadError{cause: err}
	}
	return engine, nil
}

type loadError struct{ cause error }

func (e *loadError) Error() string { return cleanError(e.cause.Error()) }
func (e *loadError) Unwrap() error { return e.cause }
func cleanError(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return '?'
		}
		return r
	}, clip(value, 1024))
}

func load(ctx context.Context, paths, parameters []string, limits Limits) (*Engine, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if len(paths) < 1 || len(paths) > MaxPlugins {
		return nil, fmt.Errorf("select 1-%d plugins", MaxPlugins)
	}
	var manifests []Manifest
	var modules [][]byte
	seen := map[string]bool{}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		manifest, module, err := loadManifest(path)
		if err != nil {
			return nil, fmt.Errorf("plugin %s: %w", path, err)
		}
		if seen[manifest.ID] {
			return nil, fmt.Errorf("duplicate plugin ID %s", manifest.ID)
		}
		seen[manifest.ID] = true
		manifests = append(manifests, manifest)
		modules = append(modules, module)
	}
	overrides, err := parseOverrides(parameters, manifests)
	if err != nil {
		return nil, err
	}
	config := wazero.NewRuntimeConfig().WithMemoryLimitPages(uint32(limits.MemoryMiB) * 16).WithCloseOnContextDone(true).WithDebugInfoEnabled(false)
	engine := &Engine{runtime: wazero.NewRuntimeWithConfig(ctx, config), limits: limits}
	failed := true
	defer func() {
		if failed {
			_ = engine.Close(context.Background())
		}
	}()
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, engine.runtime); err != nil {
		return nil, err
	}
	hostFunctions := engine.runtime.Module(wasi_snapshot_preview1.ModuleName).ExportedFunctionDefinitions()
	for index, manifest := range manifests {
		compileCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		compiled, err := engine.runtime.CompileModule(compileCtx, modules[index])
		cancel()
		if err != nil {
			return nil, fmt.Errorf("compile %s: %w", manifest.ID, err)
		}
		for _, function := range compiled.ImportedFunctions() {
			module, name, _ := function.Import()
			host, exists := hostFunctions[name]
			if module != wasi_snapshot_preview1.ModuleName || !exists || !bytes.Equal(function.ParamTypes(), host.ParamTypes()) || !bytes.Equal(function.ResultTypes(), host.ResultTypes()) {
				return nil, fmt.Errorf("plugin %s has unsupported import %s.%s", manifest.ID, module, name)
			}
		}
		start, exists := compiled.ExportedFunctions()["_start"]
		if !exists || len(start.ParamTypes()) != 0 || len(start.ResultTypes()) != 0 || len(compiled.ImportedMemories()) > 0 || compiled.ExportedMemories()["memory"] == nil {
			return nil, fmt.Errorf("plugin %s must export memory and a WASI _start command", manifest.ID)
		}
		values, err := manifest.parameters(overrides[manifest.ID])
		if err != nil {
			return nil, err
		}
		engine.bundles = append(engine.bundles, bundle{manifest: manifest, module: compiled, parameters: values, overrides: overrides[manifest.ID]})
	}
	failed = false
	return engine, nil
}

func (e *Engine) Close(ctx context.Context) error { return e.runtime.Close(ctx) }

// Manifests returns independent snapshots, safe for callers to edit without
// changing the engine's validated match rules or parameter definitions.
func (e *Engine) Manifests() []Manifest {
	result := make([]Manifest, 0, len(e.bundles))
	for _, b := range e.bundles {
		manifest := b.manifest
		manifest.Permissions = slices.Clone(manifest.Permissions)
		manifest.Match.States = slices.Clone(manifest.Match.States)
		manifest.Match.Services = slices.Clone(manifest.Match.Services)
		if manifest.Parameters != nil {
			manifest.Parameters = make(map[string]Parameter, len(b.manifest.Parameters))
			for name, parameter := range b.manifest.Parameters {
				if parameter.Minimum != nil {
					value := *parameter.Minimum
					parameter.Minimum = &value
				}
				if parameter.Maximum != nil {
					value := *parameter.Maximum
					parameter.Maximum = &value
				}
				if parameter.MaxLength != nil {
					value := *parameter.MaxLength
					parameter.MaxLength = &value
				}
				// Validated defaults are immutable string/integer/boolean scalars.
				manifest.Parameters[name] = parameter
			}
		}
		result = append(result, manifest)
	}
	return result
}

func (e *Engine) CheckCount(ports uint64) error {
	if ports > MaxRuns/uint64(len(e.bundles)) {
		return fmt.Errorf("scripts exceed %d planned host/port/plugin invocations", MaxRuns)
	}
	return nil
}

func (e *Engine) Run(ctx context.Context, result model.Result, evaluation time.Time) []model.ScriptRun {
	portCtx, cancel := context.WithTimeout(ctx, PortTimeout)
	defer cancel()
	result.Scripts = nil
	runs := make([]model.ScriptRun, 0, len(e.bundles))
	for _, b := range e.bundles {
		base := model.ScriptRun{ID: b.manifest.ID, Version: b.manifest.Version, SHA256: b.manifest.SHA256}
		if !matches(b.manifest, result) {
			base.Status, base.Reason = "skipped", "service_not_matched"
			runs = append(runs, base)
			continue
		}
		request := sdk.Request{APIVersion: sdk.APIVersion, EvaluationTime: evaluation, Parameters: b.parameters, Result: result}
		runs = append(runs, e.invoke(portCtx, b, request))
	}
	return runs
}

// Test runs one bundle with the same bounded contract used for live results.
// Fixture parameters override defaults; explicit CLI overrides take priority.
func (e *Engine) Test(ctx context.Context, request sdk.Request) (model.ScriptRun, error) {
	if len(e.bundles) != 1 {
		return model.ScriptRun{}, fmt.Errorf("fixture testing requires exactly one plugin")
	}
	data, err := json.Marshal(request)
	if err != nil {
		return model.ScriptRun{}, err
	}
	if _, err := sdk.ReadRequest(bytes.NewReader(data)); err != nil {
		return model.ScriptRun{}, err
	}
	b := e.bundles[0]
	values := make(map[string]json.RawMessage, len(request.Parameters))
	for key, value := range request.Parameters {
		values[key] = value
	}
	for key, value := range b.overrides {
		values[key] = value
	}
	parameters, err := b.manifest.parameters(values)
	if err != nil {
		return model.ScriptRun{}, err
	}
	request.Parameters = parameters
	if !matches(b.manifest, request.Result) {
		return model.ScriptRun{ID: b.manifest.ID, Version: b.manifest.Version, SHA256: b.manifest.SHA256, Status: "skipped", Reason: "service_not_matched"}, nil
	}
	return e.invoke(ctx, b, request), nil
}

func (e *Engine) invoke(parent context.Context, b bundle, request sdk.Request) (run model.ScriptRun) {
	run = model.ScriptRun{ID: b.manifest.ID, Version: b.manifest.Version, SHA256: b.manifest.SHA256, Status: "error"}
	started := time.Now()
	defer func() { run.Duration = time.Since(started) }()
	data, err := json.Marshal(request)
	if err != nil || len(data) > sdk.MaxInput {
		run.Error = "script input exceeds byte limit or cannot be encoded"
		return
	}
	ctx, cancel := context.WithTimeout(parent, e.limits.Timeout)
	defer cancel()
	stdout := &boundedBuffer{limit: sdk.MaxOutput, stop: cancel}
	stderr := &boundedBuffer{limit: MaxStderr, stop: cancel}
	config := wazero.NewModuleConfig().WithName("").WithArgs(b.manifest.ID).WithStdin(bytes.NewReader(data)).WithStdout(stdout).WithStderr(stderr)
	// WASI's default virtual clocks and randomness are isolated/deterministic;
	// checks use the host-supplied evaluation_time rather than ambient wall time.
	module, err := e.runtime.InstantiateModule(ctx, b.module, config)
	if module != nil {
		_ = module.Close(context.Background())
	}
	run.Stderr = stderr.String()
	if stdout.Exceeded() || stderr.Exceeded() {
		run.Error = "script output or stderr exceeds byte limit"
		return
	}
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			run.Status = "timeout"
		} else {
			run.Status = "canceled"
		}
		run.Error = ctx.Err().Error()
		return
	}
	var exit *sys.ExitError
	if err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 0) {
		run.Error = clip(cleanError(err.Error()), 512)
		return
	}
	var response sdk.Response
	if err := jsonwire.Decode(stdout.Bytes(), &response); err != nil {
		run.Error = clip("invalid plugin response: "+err.Error(), 512)
		return
	}
	if err := validateResponse(response, request); err != nil {
		run.Error = clip(err.Error(), 512)
		return
	}
	run.Status, run.Reason, run.Findings = response.Outcome, response.Reason, response.Findings
	run.Details = response.Details
	return
}

func validateResponse(response sdk.Response, request sdk.Request) error {
	if response.APIVersion != sdk.APIVersion || response.Outcome != "completed" && response.Outcome != "inconclusive" || len(response.Reason) > 512 || response.Outcome == "inconclusive" && response.Reason == "" || response.Outcome == "completed" && response.Reason != "" || len(response.Findings) > sdk.MaxFindings {
		return fmt.Errorf("invalid response API, outcome, reason, or finding count")
	}
	if len(response.Details) > sdk.MaxDetails {
		return fmt.Errorf("too many informational details")
	}
	data, _ := json.Marshal(request.Result)
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, finding := range response.Findings {
		if !identifier.MatchString(finding.ID) || seen[finding.ID] || finding.Kind != "observation" && finding.Kind != "match" && finding.Kind != "inconclusive" || finding.Severity != "info" && finding.Severity != "low" && finding.Severity != "medium" && finding.Severity != "high" || len(finding.Message) == 0 || len(finding.Message) > 512 || len(finding.EvidenceFields) == 0 || len(finding.EvidenceFields) > 8 {
			return fmt.Errorf("invalid finding fields or duplicate finding ID")
		}
		seen[finding.ID] = true
		for _, field := range finding.EvidenceFields {
			if !resolveField(root, field) {
				return fmt.Errorf("finding references missing or non-scalar evidence %q", field)
			}
		}
	}
	for _, detail := range response.Details {
		if len(detail.Label) == 0 || len(detail.Label) > 64 || len(detail.Value) == 0 || len(detail.Value) > 512 || len(detail.EvidenceFields) == 0 || len(detail.EvidenceFields) > 8 {
			return fmt.Errorf("invalid informational detail fields")
		}
		for _, field := range detail.EvidenceFields {
			if !resolveField(root, field) {
				return fmt.Errorf("detail references missing or non-scalar evidence %q", field)
			}
		}
	}
	return nil
}

type boundedBuffer struct {
	mu       sync.Mutex
	data     bytes.Buffer
	limit    int
	exceeded bool
	stop     context.CancelFunc
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(data) > b.limit-b.data.Len() {
		b.exceeded = true
		b.stop()
		return 0, fmt.Errorf("plugin output limit exceeded")
	}
	return b.data.Write(data)
}
func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data.Bytes()...)
}
func (b *boundedBuffer) String() string { return string(b.Bytes()) }
func (b *boundedBuffer) Exceeded() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.exceeded }
func clip(value string, limit int) string {
	if len(value) > limit {
		value = value[:limit]
	}
	if !utf8.ValidString(value) {
		value = string(bytes.ToValidUTF8([]byte(value), []byte("?")))
	}
	return value
}
