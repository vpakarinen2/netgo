# Roadmap

## Available now

- TCP connect scanning for IPv4, IPv6, CIDRs, and hostnames.
- UDP probes for DNS, NTP, and generic responses.
- HTTP, HTTPS, SSH, and TLS service identification.
- Concurrency limits, global/per-host pacing for UDP, timeouts, and retries.
- Streaming console and NDJSON output, file output, and cancellation.
- YAML/environment/flag configuration, tests, and cross-platform CI definitions.

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
