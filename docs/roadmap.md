# Roadmap

## Available now

- TCP connect scanning for IPv4, IPv6, CIDRs, and hostnames.
- Common TCP port presets: top 10, 100, and 1,000.
- UDP probes for DNS, NTP, and generic responses.
- HTTP, HTTPS, SSH, and TLS service identification.
- Concurrency limits, global/per-host pacing for UDP, timeouts, and retries.
- Shared TCP host rate/connection limits and optional scan diagnostics.
- Controlled top-1000 latency tests and a real loopback open-port regression test.
- Streaming console and NDJSON output, file output, and cancellation.
- YAML/environment/flag configuration and cross-platform source/build support.

## Possible next steps

| Area | Planned direction |
| --- | --- |
| Protocol coverage | More service signatures and UDP probes |
| UDP diagnostics | More detailed ICMP error reporting |
| Scan control | Adaptive rate limits, target shuffling, pause/resume, and checkpoints |
| Plugins | A bounded Wasm runtime with explicit permissions |
| Distribution | Release packages and installation improvements |
| Performance | Documented throughput, memory, and accuracy benchmarks |

Raw SYN scanning is deferred. It would need platform-specific packet capture,
routing, and privilege handling, starting with Linux.

These are directions rather than a release schedule. The current build does
not include raw SYN, plugins, or vulnerability validation.
