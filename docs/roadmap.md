# Roadmap

## Available now

- TCP connect scanning for IPv4, IPv6, CIDRs, and hostnames.
- Common TCP port presets: top 10, 100, and 1,000.
- UDP probes for DNS, NTP, and generic responses.
- HTTP/1.1, HTTP/2 over TLS, SSH, and TLS service identification.
- Passive Cloudflare/CloudFront/Varnish and selected WAF/challenge observations.
- Concurrency limits, global/per-host pacing for UDP, timeouts, and retries.
- Shared TCP host rate/connection limits and optional scan diagnostics.
- Bounded host rotation that skips busy budgets, including for retries.
- Controlled top-1000 latency tests and a real loopback open-port regression test.
- Streaming console, detailed text, and NDJSON output, file output, and cancellation.
- Terminal-width-aware result columns, with full columns when redirected.
- Optional open-only results, with complete summary and diagnostic counts.
- Local Wasm checks over TCP service evidence, with a Go SDK and fixture runner.
- YAML/environment/flag configuration and cross-platform source/build support.

## Possible next steps

| Area | Planned direction |
| --- | --- |
| Protocol coverage | More service signatures and UDP probes |
| UDP diagnostics | More detailed ICMP error reporting |
| Scan control | Adaptive rate limits, target shuffling, pause/resume, and checkpoints |
| Plugins | [Wasm plugin](wasm-plugins.md) network capabilities and additional lifecycle hooks |
| Distribution | Release packages and installation improvements |
| Performance | Documented throughput, memory, and accuracy benchmarks |

Raw SYN scanning is deferred. It would need platform-specific packet capture,
routing, and privilege handling, starting with Linux.

These are directions rather than a release schedule. The current build does
not include raw SYN, network-capable plugins, or vulnerability validation.
