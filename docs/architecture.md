# Architecture

## TCP/UDP scanning and service identification

The project root corresponds to the proposed `scanner/` directory. `cmd/scan`
owns process exit codes and signal handling. `internal/cli` owns Cobra command
construction and flag binding, keeping process globals out of command tests.

`configs/default.yaml` is embedded into the binary. `pkg/config` loads defaults,
an optional explicit YAML file, environment overrides, and flags using an
isolated Viper instance. It validates the effective settings before network
work can begin. It does not watch files, mutate process environment, or start
background workers.

`pkg/network/targets` parses ports and IP/CIDR/hostname inputs. It validates input
syntax and CIDR sizes before DNS, resolves unique names through a bounded worker
pool, then merges sorted address intervals and counts unique hosts. The plan
iterates lazily and retains hostname metadata separately from intervals. There
is no per-address deduplication map for CIDRs or materialized host/port product.

`pkg/model` holds shared target, method, state, service evidence, and result
types. `pkg/network.Prober` defines one cancellable probe attempt.
`pkg/output.Writer` defines a serial result sink, final summary, and explicit
flush/close behavior. `pkg/network/sockets.Connect` implements the probe;
`pkg/output` implements console and schema-v1 NDJSON writers plus file mirroring.
`pkg/core` owns scheduling, retry policy, and counters.
`pkg/service` provides embedded signatures and a cancellable inspector.
`pkg/network/sockets.UDP` sends one bounded protocol-specific datagram per
attempt and handles correlated responses and OS-delivered unreachable errors.

## Pipeline

```text
CLI + config
    -> validated interval plan / bounded DNS preflight
    -> lazy target iterator
    -> bounded work queue
    -> rate-limited probe workers
    -> optional bounded identification queue / separate worker pool
    -> bounded result queue
    -> one output coordinator
```

The dispatcher depends on narrow probe and output interfaces. Backends
must not import the dispatcher, and shared models must not import backends.
Implementations should introduce additional interfaces only at actual
substitution boundaries.

## Scheduling and resource ownership

- Jobs and result queues each hold at most the worker count. Workers are capped
  at the smaller of configured concurrency and total host/port pairs. Target
  expansion is lazy and planning has explicit input/answer/record/host limits.
- Rate limits govern new attempts; concurrency governs active probes. Retries
  consume the same budgets as first attempts. Raw packet accounting is separate.
- UDP additionally uses a fixed table of 1024 hashed host buckets. Collisions
  share a conservative budget, bounding memory independently of CIDR size.
  Global and host tokens are consumed together when ready, so waiting on one
  limit cannot accumulate stale reservations from the other. Waits release the
  table lock and honor cancellation. TCP keeps its existing global limiter.
- Optional identification workers consume finished port results through another
  queue bounded by the port worker count. Only open ports are inspected. Their
  concurrency is separate from port workers; bounded queues still propagate
  backpressure when identification or output is saturated.
- The inspector receives a connection gate tied to the same rate limiter. Every
  inspection dial consumes a token, including failed dials. `attempts` counters
  remain port-only; additional dials are recorded in `identification.connections`.
- The dispatcher owns retry policy. A prober performs one attempt, honors
  cancellation, supports concurrent calls, and releases per-attempt resources.
- Only timeout observations are retried, up to the configured additional-attempt
  count. A single shared token bucket has burst size one. Result duration is
  the final attempt duration, excluding rate waits and earlier retries.
- UDP timeout observations use open|filtered and participate in the same retry
  policy. Inline DNS/NTP service evidence requires no separate inspection stage;
  attaching the TCP identifier to a UDP run is rejected before dispatch.
- One coordinator writes results. Backpressure reaches producers; output errors
  fail the command instead of dropping results.
- Results go to stdout, diagnostics and progress to stderr. Output wrappers
  never close process stdout/stderr.

## Cancellation and failures

The first worker/producer failure cancels scheduling and in-flight probes.
SIGINT/SIGTERM cancellation follows the same path. The output coordinator keeps
draining completed results, including results already queued when cancellation
arrives. A separate watcher cancels the output context after two seconds, so a
cooperative sink already blocked in a write can also stop. On output failure,
remaining queued results are discarded while workers are joined; the failure
is returned. Owned output files close on every path.

Service workers use the scan context, not the port worker group's context:
finishing port probes must not cancel outstanding identification. During scan
cancellation, in-flight identification stops and queued open results are marked
with canceled inspection metadata, then forwarded to output. Port evidence is
preserved. An identification error never cancels the scan.

The drain deadline is cooperative: arbitrary `io.Writer` calls, including an
OS-level blocked stdout write or stalled disk I/O, cannot always be interrupted
by a context. The built-in writers check cancellation before each write. They
do not close process stdout to force an in-progress write to terminate.

Progress and result counts are owned by the coordinator. Attempt counts are
atomic because workers update them. The final summary records `completed`,
`canceled`, or `failed`; preflight failures emit no result stream. Output errors
can prevent a summary from being delivered, so consumers must also inspect the
process exit status.

## Evidence and uncertainty

A result retains the resolved address, original hostname, port, transport,
method, observation time, duration, and reason. Hostnames remain available for
HTTP Host headers and TLS SNI.

Connection refusal supports a closed TCP port; a timeout alone does not prove
filtering. UDP silence can mean open or filtered. Local resource exhaustion,
invalid inputs, and cancellation are errors rather than port-state evidence.
The [README](../README.md#targets-and-results) documents concrete TCP mappings.
Windows Winsock errors and Unix errno values are mapped separately. Cancellation
of the parent context is an error; an individual attempt deadline is a timeout
observation. DNS lookup failures abort preflight.
For UDP, a timeout after a successful send means open|filtered. A socket-reported
port unreachable supports closed; other unreachables remain unknown. The backend
does not infer filtered from silence or decode the full ICMP type/code matrix.
Setup/send deadlines are local errors. See [UDP behavior](udp.md).

## Portability

The default application uses pure Go. Raw capture and packet transmission will
be isolated behind OS-specific files and an explicit build tag, with a clear
error on unsupported platforms. Linux raw scanning comes first. Route, MTU,
gateway, link type, IPv6 neighbor discovery, and capture privileges must be
handled explicitly rather than assuming every destination is on the local LAN.

## Deferred decisions

Adaptive control, additional service signatures, deterministic target shuffling,
checkpoint format, plugin host ABI, and raw-scanner privileges remain future
work. [Service inspection](service-identification.md) has separate concurrency,
time/read bounds and preserves port evidence on failure. NDJSON v1 is documented
in [output-schema.md](output-schema.md).
