# Netgo

A terminal-based network scanner written in Go. Scan TCP and UDP ports, and identify services.

## Quick start

Requires Go 1.26 or newer.

```sh
git clone https://github.com/vpakarinen2/netgo.git
cd netgo
```

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

## Examples

On Windows, replace `./bin/scan` with `.\bin\scan.exe`.

```sh
# Default scan (TCP ports 22, 80, and 443 with built-in settings)
./bin/scan localhost

# Basic TCP scan with explicit ports
./bin/scan localhost -p 80,443,8080

# Common TCP port presets
./bin/scan localhost --top-ports 10
./bin/scan localhost --top-ports 100
./bin/scan localhost --top-ports 1000

# Identify services
./bin/scan localhost -p 22,80,443 --service

# Allow up to 3 seconds per port attempt
./bin/scan localhost -p 22,80,443 --timeout 3s

# Probe UDP services
./bin/scan localhost --transport udp -p 53,123

# Save streaming JSON results
./bin/scan localhost -p 1-1024 --format ndjson -o results.ndjson
```

Run `./bin/scan --help` for all options.

## Documentation

[Usage](docs/usage.md) ·
[Service identification](docs/service-identification.md) ·
[UDP scanning](docs/udp.md) ·
[Output format](docs/output-schema.md) ·
[Architecture](docs/architecture.md) ·
[Roadmap](docs/roadmap.md)

## Author & license

Ville Pakarinen ([@vpakarinen2](https://github.com/vpakarinen2)) ·
[Apache 2.0](LICENSE)
