# Output format

Use NDJSON when saving results or integrating Netgo with scripts:

```sh
./bin/scan localhost -p 443 --format ndjson -o results.ndjson
```

Each line is one JSON object with `schema_version: 1` and a `type` of `result`
or `summary`. Ignore unknown fields within a supported schema version.
Progress and diagnostics go to stderr. Console and `--check-config` output
use separate formats.

## Port results

This is one result line, expanded for readability:

```json
{
  "schema_version": 1,
  "type": "result",
  "result": {
    "target": {"address": "127.0.0.1", "hostname": "localhost", "port": 443, "transport": "tcp"},
    "method": "tcp-connect",
    "state": "open",
    "reason": "connected",
    "observed_at": "2026-10-17T12:00:00Z",
    "duration_ns": 1200000,
    "attempts": 1
  }
}
```

| Field | Meaning |
| --- | --- |
| `target` | Resolved IP, optional hostname, port, and `tcp` or `udp` transport |
| `method` | `tcp-connect` or `udp` |
| `state` | `open`, `closed`, `open\|filtered`, or `unknown` in current backends |
| `reason` | Observation behind the state, such as `connected` or `timeout` |
| `observed_at` | Final attempt's observation time in UTC |
| `duration_ns` | Final attempt duration; excludes rate waits and earlier retries |
| `attempts` | First port attempt plus timeout retries |
| `service` | Optional detected service and supporting evidence |
| `identification` | Optional TCP inspection status, timing, and extra connections |
| `udp` | UDP probe and reply counters |

Results arrive in completion order, once per completed unique host/port pair
unless `--open-only` hides a non-open result.
Canceled attempts and local failures do not produce port results. See
[TCP states](usage.md#reading-results) and [UDP reasons](udp.md#understanding-results).

## Optional metadata

`service` contains a detected `name`, optional `product` and `version`, and
`evidence` entries with `kind` and `value`. Supported names are `http`, `https`,
`ssh`, `tls`, `dns`, and `ntp`. Software versions are server claims.

For TCP, `identification` has:

- `status`: `identified`, `unrecognized`, `timeout`, `failed`, or `canceled`.
- `duration_ns` and `connections`: inspection time including rate waits, and
  additional dial attempts beyond the port probe.
- Optional `error`, `evidence`, and `read_limit_reached` fields.

Unknown banner bytes are JSON-escaped when valid UTF-8, otherwise base64-encoded
with a `_base64` evidence kind. `read_limit_reached` means a buffer reached its
cap; it does not prove more bytes were available. Failed identification leaves
the open-port result intact.

TLS details appear under `service.tls`: `version`, `cipher_suite`, optional
`alpn` and `server_name`, `sni_sent`, `reference_name`, `hostname_matches`, and
optional `hostname_error`. **Certificate trust is not checked:**
`certificate_verification` is `not_performed`.

Its optional `certificate` includes subject, issuer, serial, SHA-256 fingerprint,
validity dates, `time_valid`, and bounded DNS/IP name lists. `names_omitted`
counts names beyond the retained limit. See [TLS interpretation](service-identification.md#understanding-tls-results).

UDP metadata contains `probe` (`dns`, `ntp`, or `empty`), `response_bytes`,
`ignored_responses`, and `oversized_responses`. Counters cover the final attempt;
oversized replies also count as ignored. DNS/NTP can add `service` without TCP
`identification`. Reply bodies are not retained.

## Web observations

When complete HTTP headers are parsed, `service.web` contains:

| Field | Meaning |
| --- | --- |
| `edge` | Optional Cloudflare, CloudFront, and Varnish detections |
| `waf.status` | `unknown` or `signal_observed` |
| `waf.detections` | Optional AWS WAF action/status matches |
| `challenges` | Optional Cloudflare challenge observations, separate from WAF |
| `warnings` | Optional fixed codes for conflicting Server products or unmatched AWS action headers |

Detections include `provider`, `kind` (`cdn`, `cache`, `waf`, or `challenge`),
`confidence` (`low`, `medium`, `high`), and normalized `evidence` entries.
There are at most three edge detections, one WAF detection, one challenge,
and two warnings. Metadata is omitted without parsed HTTP headers.
These are response claims, not verified protection. See the [edge/WAF guide](edge-waf.md).

## Final summary

The final event has `type: summary` and a `summary` object:

| Field | Meaning |
| --- | --- |
| `status` | `completed`, `canceled`, or `failed` |
| `hosts`, `ports` | Unique addresses and ports per address |
| `total`, `completed` | Planned host/port pairs and completed observations, including deliberately hidden results |
| `reported` | Result events successfully written after output filtering |
| `open_only` | Present and true when only confirmed open results are emitted |
| `attempts` | All started port probes, including retries and failed/canceled attempts |
| `open`, `closed`, `open_filtered`, `filtered`, `unknown` | Counts among completed results |
| `started_at`, `finished_at`, `duration_ns` | UTC scan times and elapsed time, excluding DNS preflight |
| `error` | Optional failure or cancellation message |
| `diagnostics` | Optional statistics and effective settings, enabled with `--stats` |

Service connections are excluded from `attempts`. `filtered` is reserved and
currently remains zero. State counts include results hidden by `--open-only`.
For a completed scan, `completed` equals `total`, and
the five state counts sum to `completed`.

Always check the process exit code as well as the summary. Preflight failures
produce no stream; write failures may prevent a summary, and close failures can
occur after it. Mirroring stdout and a file is not atomic: one destination may
receive a line before the other fails.

## Diagnostic fields

`summary.diagnostics` is additive within schema v1:

| Field | Meaning |
| --- | --- |
| `settings` | Effective CLI configuration, including expanded port selection |
| `port_attempts`, `probe_errors` | Started port attempts and local failures, including canceled attempts |
| `active_connections`, `peak_connections` | Current/final and peak connection-budget leases, including service connections |
| `gate_wait_ns`, `probe_time_ns` | Cumulative capacity/rate waiting and port-probe time |
| `open_latency_samples`, `open_latency_total_ns` | Successful TCP attempt count and total duration; divide for the mean |
| `service_statuses` | Counts of inspection outcomes |
| `reasons` | Per-attempt reason counts, including retries; excess distinct reasons use `other` |
| `hosts` | Up to 256 addresses, each with `address`, `attempts`, `timeouts`, and `errors` |
| `unattributed_attempts` | Attempts beyond the host-detail limit, still included in global counts |

Final `active_connections` is zero once workers have joined. These counters
describe attempts rather than final port states, so retries can increase them
beyond `completed`. See the [diagnostics guide](diagnostics.md) for interpretation.
