# Usage guide

## Build and run

Requires Go 1.26 or newer. From the project folder:

```sh
go build -o bin/scan ./cmd/scan
./bin/scan localhost -p 22,80,443
```

On Windows, build with `-o bin/scan.exe` and replace `./bin/scan` in these
examples with `.\bin\scan.exe`. No administrator privileges are required.

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

| Option | Purpose | Default |
| --- | --- | --- |
| `-p`, `--ports` | Comma-separated ports and ranges | `22,80,443` |
| `--transport` | Select `tcp` or `udp` | `tcp` |
| `--service` | Identify services on open TCP ports | Off |
| `--rate` | Maximum probe starts per second, including service connections | `200` |
| `--concurrency` | Maximum concurrent port probes | `128` |
| `--timeout` | Time allowed per port attempt | `1s` |
| `--retries` | Extra attempts after a timeout | `0` |
| `--max-hosts` | Maximum unique target addresses | `65536` |
| `--max-probes` | Maximum unique host/port pairs, excluding retries | `1000000` |
| `--format` | `console` or `ndjson` | `console` |
| `-o`, `--output` | Mirror results to a new file | No file |
| `-q`, `--quiet` | Hide progress messages | Off |

Run `./bin/scan --help` for every option. See the separate guides for
[service options](service-identification.md) and [UDP options](udp.md).

## Configuration

Settings are applied in this order, highest priority first:

1. Command-line flags.
2. Environment variables starting with `NETGO_`.
3. A YAML file selected with `--config`.
4. Built-in [defaults](../configs/default.yaml).

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
Output files must be new: existing files are never overwritten.

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
