# Wasm plugins

Netgo runs custom Wasm checks against collected TCP service evidence.
Plugins are selected explicitly with `--script` and require `--service`.

The first release gives plugins scan evidence and isolated standard input/output.
Guest filesystem, environment, sockets, and shell access are unavailable. Checks
add findings; they do not change the observed port state or authenticate server claims.

## Try the examples

From the repository root, build Netgo and the example plugins:

```powershell
go build -o bin/scan.exe ./cmd/scan
go run ./tools/build-plugins

.\bin\scan.exe scripts validate tls-expiry
.\bin\scan.exe scripts test tls-expiry --input .\examples\plugins\fixtures\https.json
```

The build helper creates each `.wasm` file and a manifest with its SHA-256,
then installs the bundles into `bin/scripts` for lookup by name.
Generated modules/manifests are ignored by Git; regenerate them after source changes.

| Example | Check | Parameter |
| --- | --- | --- |
| `tls-expiry` | Certificate expired or expiring soon | `days=30`, integer 1–365 |
| `tls-hostname` | Certificate reference-name mismatch | None |
| `tls-certificate` | Collected leaf certificate details, including healthy certificates | None |
| `ssh-banner` | Reported SSH product contains text | `contains=OpenSSH` |

Run selected checks during a scan:

```powershell
.\bin\scan.exe localhost -p 443 --service --script tls-expiry --format text
```

`--format text` shows each script's status and full finding messages. Expiry and
hostname checks report their own observations without adding a certificate dump.
A completed check without observations displays `No findings.` Basic TLS protocol
details remain in the service summary; NDJSON retains collected certificate metadata.
Use `--format ndjson` for structured evidence, or omit the flag for a compact table.

For certificate information, select the dedicated script:

```powershell
.\bin\scan.exe localhost -p 443 --service --script tls-certificate --format text
```

It reports all currently collected leaf certificate fields: subject, issuer,
serial number, SHA-256 fingerprint, validity dates, retained DNS/IP names,
omitted-name count, hostname status, and trust-check status. Informational
details do not count as findings. Certificate chains, PEM, public-key details,
and other uncollected extensions are not included; chain trust is not verified.

Repeat `--script` to select more bundles, such as `--script tls-expiry --script tls-hostname`.
Optional parameter overrides use `ID.name=value`, for example
`--script-param tls-expiry.days=14`. Otherwise the plugin defaults apply.
Missing evidence produces an inconclusive result or a skipped service match.
A completed check with no findings does not establish that a service is secure.

## Script names and custom bundles

Names work with live scans and `scripts validate/test`. Netgo searches for
`<name>/plugin.yaml` in this order:

1. `scripts` beside the executable.
2. `netgo/scripts` inside the OS user configuration directory (`%APPDATA%` on Windows).
3. `../examples/plugins` relative to the executable directory (development builds).
4. `examples/plugins` inside the current working directory.

The first matching bundle is validated; its manifest ID must match the name.
For portable use, copy the `scripts` directory along with the executable.
Custom bundles can be installed in either of the first two locations, or selected
directly with `--script ./my-check/plugin.yaml`.

## Write a plugin

Use standard Go with the [SDK](../pkg/plugins/sdk/sdk.go); see the
[example sources](../examples/plugins). Build a WASI Preview 1 command:

```powershell
$env:GOOS = "wasip1"
$env:GOARCH = "wasm"
go build -trimpath -ldflags="-s -w" -o my-check.wasm ./path/to/my-check
Remove-Item Env:GOOS, Env:GOARCH
```

Keep the module next to its `plugin.yaml`. Use this manifest shape, replacing
the checksum with the module's exact lowercase SHA-256:

```yaml
api_version: netgo.script/v1
id: my-check
version: 0.1.0
description: Describe the check
author: Your name
license: Apache-2.0
module: my-check.wasm
sha256: <64 lowercase hexadecimal characters>
permissions: [scan.read]
match:
  transport: tcp
  states: [open]
  services: [ssh]
parameters: {}
```

The optional service list supports `http`, `https`, `ssh`, and `tls`.
Omit it to inspect any open TCP result. Parameters support `integer`, `string`,
and `boolean`, each with a required default. Integers can declare `minimum` and
`maximum`; strings can declare `max_length` (256 bytes by default, at most 4096).

Netgo verifies the manifest, checksum, module path, imports, and command exports
before DNS work. Modules must remain inside their bundle, including through
symlinks. Hash verification establishes file identity, not author trust.

## JSON contract

Each fresh guest instance reads one `netgo.script/v1` request on stdin and writes
one response on stdout. Stderr is reserved for bounded diagnostics.

Input contains `api_version`, `evaluation_time`, `parameters`, and `result`.
The result contains target, port, service, and inspection evidence, excluding
earlier script results. Live evaluation time is captured in UTC when the port's
checks start, after service identification and queue waiting. Fixture tests use
the time in the fixture. Use the supplied evaluation time for date checks.
The guest's default WASI clock/random sources are virtual, not host observations.

The SDK reads the request, exposes typed parameter getters, and writes the
response. Return an outcome of `completed` or `inconclusive`; the latter requires
a reason. Findings contain:

- `id`: stable finding ID, unique within the response.
- `kind`: `observation`, `match`, or `inconclusive`.
- `severity`: `info`, `low`, `medium`, or `high`.
- `message`: a nonempty description, at most 512 bytes.
- `evidence_fields`: 1–8 JSON Pointers to existing scalar fields in the result,
  such as `/service/product` or `/service/tls/certificate/not_after`.

Responses may also include `details` for informational reports. Each detail has
a `label` (1–64 bytes), `value` (1–512 bytes), and 1–8 scalar `evidence_fields`.
At most 128 details are accepted. Text output shows label/value pairs; NDJSON
retains their evidence references. Details do not increase finding counts.

Netgo supplies the plugin ID, version, hash, and target association. Findings
are plugin claims, not confirmed vulnerabilities. Duplicate JSON keys, extra
documents, unknown response fields, and unsupported API versions are rejected.
Fixture files use this request contract; a whole NDJSON event is not a request.
See [HTTPS](../examples/plugins/fixtures/https.json) and
[SSH](../examples/plugins/fixtures/ssh.json) fixtures.

## Limits and configuration

| Limit | Value |
| --- | --- |
| Selected plugins | 16 |
| Module file | 8 MiB |
| Manifest file | 64 KiB |
| Live workers | 4 by default; 1–16 |
| Guest linear memory | 64 MiB by default; 16–256 MiB |
| Aggregate configured linear memory | At most 512 MiB |
| Per-invocation deadline | 2s by default; greater than zero, at most 5s |
| Total execution budget per port | 5s |
| Input / stdout / stderr | 512 KiB / 64 KiB / 8 KiB |
| Findings per invocation | 16 |
| Informational details per invocation | 128 |
| Planned host/port/plugin invocations | 100,000 |

Live flags: `--script`, `--script-param`, `--script-timeout`,
`--script-concurrency`, and `--script-memory` (MiB).
They follow the usual flags > environment > explicit YAML > defaults priority:

```yaml
service:
  enabled: true
scripts:
  paths: ["tls-expiry"] # Script names or explicit manifest paths
  parameters: ["tls-expiry.days=14"]
  timeout: 2s
  concurrency: 4
  memory_mib: 64
```

Environment arrays must be JSON, for example
`NETGO_SCRIPTS_PATHS='["examples/plugins/tls-expiry/plugin.yaml"]'`.
Use `--check-config` to inspect settings and `scripts validate` to validate code.
The standalone `scripts validate/test` tools take their own timeout, memory, and
parameter flags; they do not load live-scan YAML or environment settings.

Deadlines cover guest initialization and execution. Live queue waiting is outside
the per-port budget, but scan cancellation applies everywhere. The pending queue
and worker count are bounded. Linear-memory limits exclude compiled code and host
allocations; this embedded runtime is not full operating-system process isolation.

## Output and failures

NDJSON keeps schema version 1 and adds `result.scripts` and `summary.scripts`.
Each run includes plugin identity/hash, status, duration, findings, and optional
reason, error, or stderr. Statuses are `completed`, `inconclusive`, `skipped`,
`error`, `timeout`, and `canceled`. Counts include hidden port rows.

Console output keeps one row per port with a compact `CHECKS` indicator and a
final script summary. Text output shows full finding messages and evidence
references in readable blocks; NDJSON includes all retained execution metadata.

Invalid selected bundles stop preflight. Runtime failures are recorded while
other scan work finishes; port observations are preserved, the final scan is
marked failed, and the process returns nonzero. Findings alone do not change
the exit code. Ctrl+C retains exit code 130.

Network-capable plugins, UDP hooks, arbitrary HTTP-header checks, and a registry
remain future work.

Runtime references: [wazero](https://pkg.go.dev/github.com/tetratelabs/wazero#RuntimeConfig),
[Go WASI support](https://go.dev/blog/wasi).
