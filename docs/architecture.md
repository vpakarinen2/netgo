# Architecture

This is a short guide for contributors. For commands and configuration, start
with the [usage guide](usage.md).

## Scan flow

```text
Load and validate settings
  -> Resolve targets and remove duplicates
  -> Generate host/port pairs as needed
  -> Run rate-limited TCP or UDP probes
  -> Identify open TCP services when requested
  -> Run explicitly selected Wasm checks when requested
  -> Stream results and a final summary
```

Target expansion is lazy, so a CIDR does not create one in-memory job for every
address and port. Bounded queues keep pending work under control.
Probes rotate across a window of up to 256 hosts (twice the worker count, with
a minimum of two). Completed hosts are replaced lazily. Hosts waiting for rate
or connection capacity are skipped, and retries rejoin the same scheduler.

## Code map

| Location | Responsibility |
| --- | --- |
| `cmd/scan` | Entrypoint, signals, and exit codes |
| `internal/cli` | Commands and flags |
| `configs`, `pkg/config` | Embedded defaults and validated settings |
| `pkg/network/targets` | IP/CIDR parsing, DNS, ports, and deduplication |
| `pkg/network/sockets` | TCP connect and UDP probes, including OS error handling |
| `pkg/core` | Workers, rate limits, retries, and scan counters |
| `pkg/service` | Banner matching, HTTP probes, and TLS inspection |
| `pkg/plugins`, `pkg/plugins/sdk` | Bounded WASI execution, bundle validation, and the authoring contract |
| `pkg/model` | Shared result and metadata types |
| `pkg/output` | Console tables, detailed text, NDJSON, and file output |

## Concurrency and limits

`--concurrency` limits active port probes. `--rate` limits probe starts,
including retries and service connections. UDP adds per-host pacing through a
fixed-size table; collisions share a budget rather than growing memory usage.
TCP optionally uses the same bounded host table for rate and connection slots.
Port probes and service dials acquire a lease, then release it after socket
cleanup, including failures. Capacity and rate tokens are acquired together;
port workers receive only eligible attempts. Service workers wait for the same
shared budgets within their inspection deadline.

TCP identification has its own worker pool. UDP identifies DNS/NTP replies
inside the original probe. A single output coordinator writes results; slow
output slows producers instead of dropping results.
Optional Wasm checks use a separate bounded worker stage after identification.
Guests analyze a result snapshot and add metadata; they receive no sockets,
filesystem mounts, or inherited environment. Plugin failures are aggregated
after draining rather than canceling otherwise valid port work.
The coordinator also owns terminal progress, clearing and redrawing it around
result rows. Optional diagnostics use bounded, synchronized counters; host
detail is limited to 256 addresses and snapshots are taken after workers join.

## Failures and cancellation

Invalid settings, DNS failures, and target limits stop the run before port
probing. Local socket errors fail the scan. Timeouts become uncertain port
results and may be retried. Service inspection failures preserve open-port evidence.

Ctrl+C cancels scheduling and closes active network operations. Completed
results are drained for up to two seconds with cooperative writers. A blocked
OS-level stdout or disk write may outlast that limit. Output failures can
prevent delivery of the final summary, so callers must check the exit code.

The current backends require no raw sockets or capture libraries. Raw SYN and
network-capable plugins remain [future work](roadmap.md). See [Wasm checks](wasm-plugins.md)
and the [output format](output-schema.md)
for the public result contract.
