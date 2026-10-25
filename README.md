# NetGo

A terminal-based network scanner written in Go. Scan TCP and UDP ports, and identify services.

## Quick start

Requires Go 1.26.10 or newer. Builds select Go 1.27.3 or newer automatically.

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

## Output

```
./bin/scan example.com --top-ports 10 --service

ADDRESS                                  PORT       STATE          REASON                HOSTNAME              SERVICE  PRODUCT/VERSION     EDGE                  WAF                 IDENTIFICATION
162.xxx.xxx.xx                           80/tcp     open           connected             example.com           http     cloudflare          cloudflare [high]     unknown             identified
162.xxx.xxx.xx                           443/tcp    open           connected             example.com           https    cloudflare          cloudflare [high]     unknown             identified
151.xxx.xxx.x                            80/tcp     open           connected             example.com           http     Varnish             varnish [high]        unknown             identified
151.xxx.x.x                              443/tcp    open           connected             example.com           https    Varnish             varnish [high]        unknown             identified
151.xxx.xxx.x                            443/tcp    open           connected             example.com           https    Varnish             varnish [high]        unknown             identified
151.xxx.x.x                              80/tcp     open           connected             example.com           http     Varnish             varnish [high]        unknown             identified
```

## Examples

Run `./bin/scan --help` for all options.

```sh
# Basic TCP scan with explicit ports
./bin/scan localhost -p 80,443,8080

# Common TCP port presets
./bin/scan localhost --top-ports 10
./bin/scan localhost --top-ports 100
./bin/scan localhost --top-ports 1000

# Identify services
./bin/scan localhost -p 22,80,443 --service

# Read detailed service and script results
./bin/scan localhost -p 443 --service --format text

# Show certificate information (build plugins once: go run ./tools/build-plugins)
./bin/scan localhost -p 443 --service --script tls-certificate --format text

# Show only open ports
./bin/scan localhost --top-ports 100 --open-only

# Set timeout
./bin/scan localhost -p 22,80,443 --timeout 3s

# Limit connection pressure
./bin/scan localhost --top-ports 1000 --timeout 3s --tcp-host-rate 20 --tcp-host-concurrency 16

# Probe UDP services
./bin/scan localhost --transport udp -p 53,123

```

## Documentation

[Usage](docs/usage.md) ·
[Service identification](docs/service-identification.md) ·
[Edge & WAF](docs/edge-waf.md) ·
[Wasm plugins](docs/wasm-plugins.md) ·
[UDP scanning](docs/udp.md) ·
[Output format](docs/output-schema.md) ·
[Architecture](docs/architecture.md) ·
[Roadmap](docs/roadmap.md)

## Author & license

Ville Pakarinen ([@vpakarinen2](https://github.com/vpakarinen2)) ·
[Apache 2.0](LICENSE)
