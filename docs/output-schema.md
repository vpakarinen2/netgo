# NDJSON schema v1

`--format ndjson` emits one compact JSON object per line. All events contain
`schema_version: 1` and `type`. Consumers should ignore additional fields within
a supported schema version. Console output and `--check-config` are separate
formats and do not use this envelope.

## Result event

```json
{"schema_version":1,"type":"result","result":{"target":{"address":"127.0.0.1","hostname":"localhost","port":443,"transport":"tcp"},"method":"tcp-connect","state":"open","reason":"connected","observed_at":"2026-10-16T12:00:00Z","duration_ns":1200000,"attempts":1}}
```

- Exactly one final result is emitted per completed unique host/port pair.
- `target.address` is a resolved IP; `hostname` is optional. IPv6 addresses use
  their normal textual representation without brackets in this field.
- `target.port` is an integer; `transport` is `tcp` or `udp`.
- `method` is `tcp-connect` or `udp`.
- `state` is `open`, `closed`, `open|filtered`, or `unknown`; `reason` provides the
  concrete observation. See the README for mappings.
- `observed_at` is the final attempt's observation time in UTC RFC3339 format,
  with fractional seconds when needed.
- `duration_ns` is the final attempt duration in nanoseconds, including socket
  cleanup but excluding rate waiting and previous attempts.
- `attempts` includes the first attempt and any timeout retries.
- Optional `service` and `identification` fields describe enabled service inspection.

Results are emitted in completion order. No global sorting buffer is used.
Canceled in-flight attempts and local failures are not emitted as port results.

## UDP metadata

UDP results include `udp`, for example:

```json
{"probe":"dns","response_bytes":17,"ignored_responses":0,"oversized_responses":0}
```

`probe` is the actual payload (`empty`, `dns`, or `ntp`), after resolving `auto`.
`response_bytes` is the matching reply length (zero also permits a matched empty
generic datagram). Ignored/oversized counters describe the final attempt;
oversized replies are included in `ignored_responses`. At most 64 rejected
replies are processed per attempt. No response body is retained in these fields.
DNS/NTP matches can include inline `service` evidence without `identification`
metadata or extra connections. Generic replies do not imply a protocol name.

UDP reasons are `udp_response`, `port_unreachable`, `timeout`,
`network_unreachable`, `host_unreachable`, or `response_limit`. `timeout` after
a successful send maps to `open|filtered`; reaching the invalid-reply limit
maps to `unknown`. Setup/send failures are errors, not silent-port results.

## Service metadata

With `--service`, completed open-port results also have `identification`:

```json
{"status":"identified","duration_ns":250000000,"connections":3}
```

- `status`: `identified`, `unrecognized`, `timeout`, `failed`, or `canceled`.
- `duration_ns`: inspection time including its connection/rate waits.
- `connections`: additional dial attempts, excluding the original port probe.
- `error`: optional diagnostic, limited to 512 bytes. It can accompany an
  identified TLS service when the subsequent HTTP probe failed.
- `evidence`: optional unrecognized banner/response evidence. Invalid UTF-8 uses
  base64 with a `_base64` kind suffix; otherwise JSON escaping preserves bytes
  representable as UTF-8, including control characters.
- `read_limit_reached`: optional true when a banner/HTTP buffer reached its cap;
  this does not prove additional bytes were available.

When detected, `service` contains `name` (`http`, `https`, `ssh`, `tls`, `dns`, or `ntp`),
optional claimed `product`/`version` (up to 128 bytes each), and evidence such as
`banner`, `http_status`, `http_server`, or negotiated `alpn: h2`. HTTP and SSH
software versions are untrusted server claims. No service is guessed from its
port number. Unrecognized or failed inspections can omit `service` while
retaining `state: open` and the original port timings/reason/attempts.

TLS/HTTPS services additionally include `service.tls`: protocol `version`,
`cipher_suite`, optional `alpn`/`server_name`, `sni_sent`, `reference_name`,
`hostname_matches`, optional `hostname_error`, and
`certificate_verification: not_performed`. Certificate chain trust is not
validated. `certificate` contains subject/issuer, decimal serial, SHA-256 of the
leaf DER certificate, UTC validity dates, `time_valid`, and bounded DNS/IP SAN
lists. See [service-identification.md](service-identification.md) for field caps.

Canceled identification preserves completed open-port observations. Closed and
unknown port results have no TCP identification metadata. These fields are additive
within schema v1; clients should continue to ignore unrecognized fields.

## Summary event

```json
{"schema_version":1,"type":"summary","summary":{"status":"completed","hosts":1,"ports":1,"total":1,"completed":1,"attempts":1,"open":1,"closed":0,"unknown":0,"started_at":"2026-10-16T12:00:00Z","finished_at":"2026-10-16T12:00:00.002Z","duration_ns":2000000}}
```

The summary is the final event when the output sink remains writable:

- `status`: `completed`, `canceled`, or `failed`.
- `hosts`: unique addresses in the plan; `ports`: unique ports per address.
- `total`: planned host/port pairs, excluding retries.
- `completed`: final results successfully written through the selected router.
- `attempts`: every started port probe, including failed or canceled attempts;
  additional service connections are excluded.
- `open`, `closed`, `open_filtered`, `filtered`, `unknown`: counts among completed
  results. `filtered` is reserved for confirmed filtering evidence and currently
  remains zero with these socket backends.
- `started_at`, `finished_at`: UTC scan times, excluding DNS preflight.
- `duration_ns`: elapsed scan time including rate waits and result draining.
- `error`: optional diagnostic for failure or cancellation.

For a completed scan, `completed == total` and the five state counts sum to
`completed`. Interrupted/failed scans can have fewer results than `total`.
Summary duration is measured before writing the summary and closing output.

Invalid input, DNS errors, target limits, and output-file creation errors happen
before the stream begins. Write/close failures can prevent delivery of a final
summary, or fail after it has been written. Consumers must check process exit
status as well as the summary. Mirroring stdout and a file is not an atomic
transaction: one destination can receive a line before another fails.
