# Usage guide

## Build and run

Requires Go 1.26 or newer. From the project folder:

Windows (PowerShell):

```powershell
go build -o bin/scan.exe ./cmd/scan
.\bin\scan.exe localhost -p 22,80,443
```

Linux/macOS:

```sh
go build -o bin/scan ./cmd/scan
./bin/scan localhost -p 22,80,443
```

Each command builds for your current operating system. The source directory
is always `./cmd/scan`, including on Windows.

In the examples below, Windows users should replace `./bin/scan` with
`.\bin\scan.exe`. No administrator privileges are required.

## Common tasks

```sh
# Scan multiple targets or a subnet
./bin/scan localhost 127.0.0.1 -p 8000-8010
./bin/scan 192.0.2.0/28 -p 80,443

# Identify services on open TCP ports
./bin/scan localhost -p 22,80,443 --service

# Probe UDP services
./bin/scan localhost --transport udp -p 53,123

# Save results as one JSON object per line
./bin/scan localhost -p 1-1024 --format ndjson -o results.ndjson
```

Targets can be IPv4/IPv6 addresses, CIDRs, or ASCII hostnames. Duplicate
addresses and ports are scanned once. CIDRs include network and broadcast
addresses. URLs, `host:port`, scoped IPv6, and address-range syntax are unsupported.
DNS lookup errors stop the scan before port probing begins.

## Useful options

Choose a common TCP port preset instead of listing ports:

```sh
./bin/scan localhost --top-ports 10
./bin/scan localhost --top-ports 100
./bin/scan localhost --top-ports 1000 --service
```

These are fixed common-port lists, not ports 1–100 or live popularity rankings.
The default stays `22,80,443`. Presets are TCP-only; use `--ports` for UDP.
The 100/1000 lists come from Naabu; the 10-port quick preset is a Netgo selection.
See [source and license notices](../THIRD_PARTY_NOTICES.md).

| Option | Purpose | Default |
| --- | --- | --- |
| `-p`, `--ports` | Comma-separated ports and ranges | `22,80,443` |
| `--top-ports` | Common TCP ports: `10`, `100`, or `1000` | `0` (disabled) |
| `--transport` | Select `tcp` or `udp` | `tcp` |
| `--service` | Identify services on open TCP ports | Off |
| `--rate` | Maximum probe starts per second, including service connections | `200` |
| `--concurrency` | Maximum concurrent port probes | `128` |
| `--tcp-host-rate` | TCP connection starts per host/second, including service connections | `0` (disabled) |
| `--tcp-host-concurrency` | TCP connection slots per host, shared with service connections | `0` (disabled) |
| `--timeout` | Time allowed per port attempt | `1s` |
| `--retries` | Extra attempts after a timeout | `0` |
| `--max-hosts` | Maximum unique target addresses | `65536` |
| `--max-probes` | Maximum unique host/port pairs, excluding retries | `1000000` |
| `--format` | `console` or `ndjson` | `console` |
| `--open-only` | Show only confirmed open port results | Off |
| `-o`, `--output` | Mirror results to a new file | No file |
| `-q`, `--quiet` | Hide progress messages | Off |
| `--stats` | Include diagnostic statistics in the final summary | Off |

Run `./bin/scan --help` for every option. See the separate guides for
[service options](service-identification.md) and [UDP options](udp.md).

## Configuration

Settings are applied in this order, highest priority first:

1. Command-line flags.
2. Environment variables starting with `NETGO_`.
3. A YAML file selected with `--config`.
4. Built-in [defaults](../configs/default.yaml).

Port selection follows the same priority: an explicit `--ports` replaces an
inherited preset, and `--top-ports` replaces an inherited port list. At the same
level, set only one selector. Use `scan.top_ports` in YAML or
`NETGO_SCAN_TOP_PORTS` in the environment; `0` disables the preset.
`--check-config` includes the expanded port list.

For environment variables, uppercase the YAML section and key and join them
with underscores: `scan.timeout` becomes `NETGO_SCAN_TIMEOUT`.

```yaml
scan:
  ports: "22,80,443"
  timeout: 2s
  rate: 100
```

Save this as `scan.yaml`, then run:

```sh
./bin/scan localhost --config scan.yaml
./bin/scan --config scan.yaml --check-config
```

`--check-config` prints the effective settings without scanning. Config files
are loaded only when requested. Unknown YAML keys and invalid values are rejected;
keep port lists quoted, even for one port.

## Reading results

| State | Meaning |
| --- | --- |
| `open` | A TCP connection or matching UDP reply succeeded |
| `closed` | The connection was refused or a UDP port-unreachable error was reported |
| `open\|filtered` | UDP received no accepted reply before its deadline |
| `unknown` | There was insufficient evidence, such as a TCP timeout |

Results appear as probes finish. Long console values are shortened; NDJSON
preserves full values. Results go to stdout, progress and errors to stderr.
Interactive console progress updates one line; redirected output and NDJSON
mode use plain progress lines. `--quiet` hides progress without hiding statistics.
Output files must be new: existing files are never overwritten.

Use `--open-only` to hide closed and uncertain rows in console, NDJSON, and file
output. Summaries and statistics still count all scanned ports; `reported`
counts the result rows actually shown. `open|filtered` UDP ports are hidden
because they are not confirmed open. YAML: `output.open_only`; environment:
`NETGO_OUTPUT_OPEN_ONLY`.

For slower or larger scans, see [diagnostics and connection limits](diagnostics.md).

Press Ctrl+C to cancel. Exit codes are `0` for a completed scan, `1` for an
error, and `130` for cancellation. A completed scan may still contain uncertain
port states. For scripts, see the [output format](output-schema.md).

## Development

```sh
go test ./...
go vet ./...
go test -race ./...
```

Tests use local listeners. Race testing requires a supported platform and a C
compiler. GNU Make users can also run `make check` and `make fuzz`.

For a container build:

```sh
docker build -t netgo .
docker run --rm netgo --help
```

The container runs as a non-root user. Reachability depends on its network setup.
