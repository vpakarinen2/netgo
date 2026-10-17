# UDP scanning

Choose UDP explicitly and provide the ports you want to probe:

```sh
./bin/scan localhost --transport udp -p 53,123
```

UDP uses ordinary sockets and needs no elevated privileges. The default port
list remains `22,80,443`, so always specify appropriate UDP ports.
`--top-ports` presets are TCP-only.

## Choosing a probe

| `--udp-probe` | What Netgo sends |
| --- | --- |
| `auto` (default) | DNS on port 53, NTP on port 123, empty datagrams elsewhere |
| `dns` | A nonrecursive root NS query |
| `ntp` | An NTP client request |
| `empty` | A zero-length datagram |

Force a probe when a service uses a nonstandard port:

```sh
./bin/scan localhost --transport udp -p 5353 --udp-probe dns
```

Replies must come from the selected address and port. DNS/NTP replies must also
match the request's transaction data. Matching replies add service evidence
automatically; `--service` is TCP-only and cannot be used with UDP.

## Understanding results

| Observation | State | Reason |
| --- | --- | --- |
| Matching reply | `open` | `udp_response` |
| OS reports port unreachable | `closed` | `port_unreachable` |
| No accepted reply after a successful send | `open\|filtered` | `timeout` |
| Network or host unreachable | `unknown` | `network_unreachable` / `host_unreachable` |
| 64 rejected replies | `unknown` | `response_limit` |

**Silence is inconclusive.** A service may ignore the request, or a packet may
be lost or blocked. Only timeout results are retried. Even a DNS error response
or NTP rate-limit reply can confirm an open service.

Netgo uses errors reported by the OS, without capturing ICMP packets. Closed-port
detection depends on which errors the OS and network deliver. Full ICMP type/code
decoding and confirmed `filtered` results are not implemented. Local setup/send
failures stop the command instead of becoming port-state evidence.

## Tuning

| Option | Purpose | Default |
| --- | --- | --- |
| `--timeout` | Time allowed per attempt | `1s` |
| `--retries` | Extra attempts after silence | `0` |
| `--rate` | Global probe starts per second | `200` |
| `--udp-host-rate` | Probe starts per host per second, including retries | `20` |
| `--udp-max-bytes` | Largest accepted reply, from 48 to 65535 bytes | `4096` |

Oversized and unrelated replies are ignored without extending the deadline.
Per-host pacing uses a bounded shared table, so some hosts can share a rate
budget. Each attempt uses a fresh socket. Broadcast sending and multicast
membership are not enabled.

NDJSON includes the probe name, matched reply size, and rejected-reply counts
for the final attempt. Reply bodies are not saved. See the
[output format](output-schema.md) and [usage guide](usage.md).
