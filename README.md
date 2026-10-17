# Netgo

A terminal-based network scanner written in Go. The executable is called `scan`.

Netgo scans IPv4, IPv6, CIDRs, and hostnames without elevated
privileges. It provides bounded concurrency, a shared rate budget, timeout
retries, streaming console/NDJSON results, progress counters, and optional file
output. Opt-in service identification detects HTTP, HTTPS, SSH, and TLS.
UDP scanning includes DNS/NTP probes and conservative silence handling.
Raw SYN is deferred; plugins remain planned.

## Requirements

- Go 1.26 or newer; use the latest patch of a supported release.
- No administrator privileges, packet capture libraries, or C compiler are needed
  for the default build.

The Go module path is `github.com/vpakarinen2/netgo`.

## Build and run

From the project root:

```sh
go mod download
go build -o bin/scan ./cmd/scan
go run ./cmd/scan --help
go run ./cmd/scan --version
go run ./cmd/scan --check-config
go run ./cmd/scan --config configs/default.yaml --rate 100 --check-config
go run ./cmd/scan 127.0.0.1 --ports 22,80,443
go run ./cmd/scan localhost --ports 8000-8010 --format ndjson --quiet
go run ./cmd/scan 192.0.2.0/28 --rate 100 --format ndjson --output results.ndjson
go run ./cmd/scan localhost --ports 22,80,443 --service --format ndjson
go run ./cmd/scan 127.0.0.1 --ports 8443 --service --sni example.test --format ndjson
go run ./cmd/scan 127.0.0.1 --transport udp -p 53,123 --format ndjson
go run ./cmd/scan 127.0.0.1 --transport udp -p 5353 --udp-probe dns --retries 1
```

On Windows, build with `go build -o bin/scan.exe ./cmd/scan`. `go run` works with
the same arguments on every supported platform.

`--check-config` prints the effective configuration as a single pretty-printed
JSON document to stdout, including a timeout such as `"1s"`. It takes no target
arguments and performs no DNS resolution or scanning. `--format` selects the
scan result format; it does not change configuration-check output. `--output`
does not create files in check mode.

Help and version do not load user configuration. Other failures produce a
diagnostic on stderr and exit with status 1. Success exits with 0; context
cancellation exits with 130. SIGINT and, where supported, SIGTERM cancel the
command context. A completed scan can include `unknown` results and still exit
successfully; success means the requested work finished, not that every port's
state could be determined.

## Targets and results

Pass IP addresses, CIDRs, or ASCII hostnames as separate arguments. IPv4-mapped
IPv6 addresses are normalized to IPv4. Overlapping CIDRs, repeated IPs, and DNS
answers are deduplicated. Every address in a CIDR is included, including IPv4
network and broadcast addresses. Addresses are enumerated lazily in numeric
order; results are emitted in completion order.

Unique hostnames are resolved once per scan, with bounded parallelism and a
per-name timeout. The first hostname associated with an address is retained
in results, even when that address also occurs in a CIDR. Names are lowercased
and their final dot is removed from result metadata. Scoped IPv6 addresses,
URLs, host:port inputs, and address-range syntax are not supported in this MVP.

Preflight rejects scans above `--max-hosts` or `--max-probes` before opening an
output file or sending scan probes. The latter counts unique host/port pairs;
retries are additional attempts. Planning allows at most 4096 input arguments,
256 addresses per hostname, and 65536 address records before interval merging.
DNS errors abort planning instead of silently omitting targets.

| Observation | State | Reason |
| --- | --- | --- |
| TCP handshake succeeds | `open` | `connected` |
| Connection refused | `closed` | `connection_refused` |
| TCP attempt deadline expires | `unknown` | `timeout` |
| Network/host unreachable | `unknown` | `network_unreachable` / `host_unreachable` |
| Reset during connection establishment | `unknown` | `connection_reset` |

Only port-scan timeouts are retried. Port probes, retries, and additional service
connections use the same token bucket with burst size one. A port-scan handshake
is closed immediately, without sending application data. Local port-scan failures such as socket exhaustion
or access denial fail the scan and are never reported as closed ports.

Results and the final summary go to stdout. Progress starts at zero and is
printed to stderr roughly once per second; `--quiet` suppresses it. `--output`
mirrors the selected result format to a new file and refuses to overwrite an
existing path. Write/close failures fail the command. NDJSON is documented in
[the output schema](docs/output-schema.md).
Console columns use fixed widths for streaming alignment. Long values are
shortened with `...`; use NDJSON for their full values.

## UDP scanning

Select `--transport udp` and a port list, for example `-p 53,123`. The existing
default port list (`22,80,443`) is unchanged for both transports, so specify UDP
ports explicitly. Scans use connected UDP sockets without raw capture privileges.

`--udp-probe auto` sends a nonrecursive root NS DNS query on port 53, an NTP
client request on 123, and an empty datagram elsewhere. Force `dns`, `ntp`, or
`empty` for nonstandard ports. DNS/NTP replies must match the request; malformed,
unrelated, and oversized replies are ignored within bounded limits. A matching
reply confirms `open`; an OS-reported port-unreachable error confirms `closed`.
Silence after a successful send is `open|filtered` with reason `timeout`, and
can be retried with `--retries`. Other unreachable errors remain `unknown`.

UDP attempts share `--rate` and have an additional `--udp-host-rate` limit
(default 20/second, including retries). Host limits use a bounded table; hash
collisions conservatively share a budget. Matched DNS/NTP replies include service
evidence automatically. `--service` is TCP-only and is rejected for UDP.

Progress/summaries distinguish `open|filtered`, `filtered`, and `unknown`.
This backend does not decode all ICMP type/code combinations or claim a
confirmed filtered state from silence. See [UDP scanning](docs/udp.md) for
protocol matching, OS behavior, limits, and result metadata.

## Service identification

`--service` inspects open ports through a separate bounded worker pool. It first
reads a banner, then (if the connection is silent) tries TLS and HTTP `HEAD /`.
Use `--service --service-active=false` for banner reads without application
payloads. Unknown nonempty banners are retained as evidence without active
probing. Closed/unknown ports are not inspected. There are no service retries.

Identification can add at most three connections per open port, all subject to
`--rate`. `--max-probes` still counts port-scan host/port pairs. Inspection
timeouts/failures are returned as metadata and preserve the open port result.
`--service-timeout` includes time spent waiting for rate tokens, so low rate
limits can leave insufficient time for identification.

TLS output includes SNI, ALPN, protocol/cipher, certificate fingerprint and
validity dates, plus offline hostname and time checks. Certificate chain trust
is **not checked**: `certificate_verification` is `not_performed`. Name/time
matches do not establish certificate trust. `--sni` overrides the TLS reference
name, SNI, and HTTP Host while keeping connections on the resolved target IP.

See [service identification](docs/service-identification.md) for budgets,
evidence, protocol coverage, and TLS inspection details.

## Configuration

Precedence, highest first:

1. Explicit command-line flags, even when equal to the default value.
2. Environment variables prefixed with `NETGO_`.
3. A YAML file explicitly selected with `--config`.
4. Embedded [defaults](configs/default.yaml).

The program never searches the working directory or home directory for config
files. An explicitly requested missing file is an error. YAML keys are checked
strictly; unknown keys fail validation. Empty environment values are considered
overrides and fail when invalid. File syntax, key names, and decoded field types
are checked before applying overrides; range constraints apply to the effective
configuration.

| Flag | Environment variable | YAML key | Default | Accepted values |
| --- | --- | --- | --- | --- |
| `--ports`, `-p` | `NETGO_SCAN_PORTS` | `scan.ports` | `22,80,443` | Comma-separated ports/ranges, 1–65535 |
| `--transport` | `NETGO_SCAN_TRANSPORT` | `scan.transport` | `tcp` | `tcp`, `udp` |
| `--udp-probe` | `NETGO_UDP_PROBE` | `udp.probe` | `auto` | `auto`, `empty`, `dns`, `ntp` |
| `--udp-host-rate` | `NETGO_UDP_HOST_RATE` | `udp.host_rate` | `20` | 1–1000000 attempts/second per host |
| `--udp-max-bytes` | `NETGO_UDP_MAX_BYTES` | `udp.max_bytes` | `4096` | 48–65535 accepted response bytes |
| `--concurrency` | `NETGO_SCAN_CONCURRENCY` | `scan.concurrency` | `128` | 1–65535 |
| `--rate` | `NETGO_SCAN_RATE` | `scan.rate` | `200` | 1–1000000 probe starts/second, including TCP services |
| `--timeout` | `NETGO_SCAN_TIMEOUT` | `scan.timeout` | `1s` | Positive Go duration, at most `1m` |
| `--retries` | `NETGO_SCAN_RETRIES` | `scan.retries` | `0` | 0–10 additional attempts after timeout |
| `--max-hosts` | `NETGO_SCAN_MAX_HOSTS` | `scan.max_hosts` | `65536` | 1–1000000 unique addresses |
| `--max-probes` | `NETGO_SCAN_MAX_PROBES` | `scan.max_probes` | `1000000` | 1–100000000 host/port pairs |
| `--dns-concurrency` | `NETGO_DNS_CONCURRENCY` | `dns.concurrency` | `16` | 1–256 |
| `--dns-timeout` | `NETGO_DNS_TIMEOUT` | `dns.timeout` | `3s` | Positive Go duration, at most `1m` |
| `--service` | `NETGO_SERVICE_ENABLED` | `service.enabled` | `false` | Boolean |
| `--service-active` | `NETGO_SERVICE_ACTIVE` | `service.active` | `true` | Boolean; used with `--service` |
| `--service-concurrency` | `NETGO_SERVICE_CONCURRENCY` | `service.concurrency` | `16` | 1–256 inspections |
| `--service-timeout` | `NETGO_SERVICE_TIMEOUT` | `service.timeout` | `3s` | Positive duration, at most `1m` |
| `--service-max-bytes` | `NETGO_SERVICE_MAX_BYTES` | `service.max_bytes` | `8192` | 256–65536 bytes per banner/HTTP response |
| `--sni` | `NETGO_SERVICE_SERVER_NAME` | `service.server_name` | empty | ASCII DNS hostname |
| `--format` | `NETGO_OUTPUT_FORMAT` | `output.format` | `console` | `console`, `ndjson` |
| `--output`, `-o` | `NETGO_OUTPUT_FILE` | `output.file` | empty | New output file path |
| `--quiet`, `-q` | `NETGO_OUTPUT_QUIET` | `output.quiet` | `false` | Boolean |

Keep `scan.ports` quoted in YAML, including single-port specifications. Port
ranges are inclusive; duplicates are removed and parsed ports are sorted.

## Development

```sh
go test ./...
go vet ./...
go test -race ./...
go test ./pkg/network/targets -run=^$ -fuzz=FuzzParsePorts -fuzztime=10s
go test ./pkg/network/targets -run=^$ -fuzz=FuzzSpanUnion -fuzztime=10s
go test ./pkg/service -run=^$ -fuzz=FuzzFingerprint -fuzztime=10s
go test ./pkg/network/sockets -run=^$ -fuzz=FuzzUDPReplyMatching -fuzztime=10s
```

Race detection requires a supported platform and C compiler. CI runs tests,
vet, and builds on Windows, Linux, and macOS with Go 1.26 and 1.27, plus race
detection and bounded fuzzing on Linux. `make check` is available with GNU Make
and a POSIX shell. PowerShell users can run the Go commands directly.
Tests use loopback listeners and injected DNS/dial errors; no public-network
scans are required. Tests must be allowed to connect to local listeners.

```sh
docker build -t netgo .
docker run --rm netgo --check-config
```

The container runs as a non-root user and needs no network capabilities for
TCP connect and UDP scanning. Raw SYN scanning will have a separate optional build and
documented platform requirements when implemented.

See [architecture](docs/architecture.md) and [roadmap](docs/roadmap.md) for the
boundaries and remaining milestones. Unimplemented packages are intentionally
not represented by empty placeholder files.

## Author

Ville Pakarinen (@vpakarinen2)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
