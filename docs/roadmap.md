# Roadmap

## 1. Foundation — implemented

- Go module, CLI help/version, signal-aware entrypoint.
- Embedded defaults, explicit YAML, environment and flag precedence.
- Strict configuration and port validation; effective-config JSON output.
- Shared data types and probe/output contracts.
- Unit tests, parser fuzz seeds, build files, CI, and developer documentation.

CI and Docker definitions are provided; a checked-in workflow is not evidence
that hosted jobs or a container build have run.

## 2. TCP connect MVP — implemented

Implemented lazy IPv4/IPv6/CIDR enumeration using merged intervals, hostname
resolution with bounded per-plan caching, bounded worker scheduling, a shared
token bucket, TCP connect probes, timeout retries, streaming console/NDJSON
output, final summaries, progress, and exclusive-create file mirroring.
Hostname context survives overlap deduplication. Host and host/port product
limits are checked before dispatch; CIDR sizes are checked before expansion.

Acceptance: local fixtures verify listening/refused/timed-out observations;
concurrency and rate bounds hold; cancellation terminates producers and workers;
all sockets close; completed results drain within two seconds with cooperative
sinks (see the architecture's I/O limitation);
output errors propagate. No public-network scans are required by tests.

## 3. Service identification — implemented

Implemented opt-in size/time-bounded banner reads, embedded HTTP/SSH YAML
signatures, optional TLS handshakes and HTTP HEAD probes, HTTPS identification,
HTTP/2 ALPN evidence, leaf certificate/SNI/hostname/time inspection, and a
separate bounded worker pool sharing the global connection rate budget.
Inspection failures preserve the original port observation. Chain trust is not
validated; STARTTLS, client certificates, and additional protocols remain future
work. Tests use local HTTP/TLS servers, banner fixtures, generated self-signed
certificates, and bounded in-memory connections, covering mismatch/expiry,
byte/time limits, cancellation, and open-port evidence preservation.

## 4. Raw SYN scanning — deferred

Skipped at the user's request to implement UDP next. No raw SYN backend or
capture privileges are included in the current build.

Add packet construction/checksums, route/interface selection, packet capture,
response correlation, timeout/retry handling, and explicit privilege checks.
Start with Linux and isolate native dependencies from the default build.
Validate in an isolated network lab against packet captures, including
unrelated or late responses, capture loss, RST handling, and routed traffic.

## 5. UDP scanning — implemented

Implemented connected-socket IPv4/IPv6 probes for DNS, NTP, and empty datagrams;
request/reply matching; byte and invalid-reply limits; OS port-unreachable error
mapping (including Windows reporting setup); timeout retries; shared global and
bounded per-host pacing; inline DNS/NTP service evidence; and distinct
open|filtered summary counters. Tests cover real loopback replies, silence,
ICMP port-unreachable reports, malformed/oversized/wrong-source replies, pacing,
and cancellation. Full ICMP type/code decoding remains future work.

## 6. Wasm plugins

Use wazero for explicitly selected detection plugins with a versioned host API,
bounded memory, cancellation/deadlines, and host-controlled I/O permissions.
Test isolation, runaway execution cancellation, and failure containment.

## 7. Production hardening

Add adaptive rate control, deterministic address shuffling, pause/resume,
checkpoint compatibility, packaging, and optional raw-scanner build images.
Measure memory, socket usage, throughput, cancellation time, and result accuracy
on documented workloads. Validate resource behavior before making performance
claims or describing a release as production ready.

## Dependency policy

Use Go 1.26 as the current minimum and test with Go 1.27. Prefer current patch
toolchains. The foundation uses the requested Cobra v1.8.1 and Viper v1.19.0;
pflag is a direct dependency because configuration binds flag sets explicitly.

The TCP milestone adds x/time v0.7.0 and x/sync v0.8.0. x/sys v0.18.0, already
transitive in the foundation, is now direct for Windows Winsock constants.
Console output currently uses the standard library. Consider pterm for richer
terminal presentation, gopacket for raw scanning, and wazero for plugins.
Recheck compatibility and
security advisories when introducing or upgrading dependencies. Commit go.sum.
Service identification makes the existing yaml.v3 v3.0.1 dependency direct for
embedded signatures; it adds no new dependency versions.
UDP adds the originally proposed miekg/dns v1.1.62 for bounded DNS packet
encoding/decoding. Its module requirements update x/sys to v0.22.0 and indirect
x/net/x/text/tooling dependencies; go.mod and go.sum record the resolved versions.
