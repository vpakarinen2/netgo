# Diagnostics and connection limits

Use `--stats` to help compare scans without guessing why ports timed out:

```sh
./bin/scan localhost --top-ports 1000 --timeout 3s --tcp-host-rate 20 --tcp-host-concurrency 16 --stats
```

TCP host limits apply to port attempts, retries, and service connections together.
`--rate` and `--concurrency` still apply; service workers also have their own
concurrency setting. Capacity and rate tokens are acquired together, and the
slot is released after the connection closes. Both TCP host limits default to `0` (disabled).
UDP keeps its separate `--udp-host-rate` setting.

Host budgets use 1024 shared buckets to bound memory. Some addresses can share
a bucket and therefore a more restrictive budget. The port scheduler skips busy
hosts within its bounded window; service workers wait without holding a socket.
Service budget waits count toward
`--service-timeout`, so very low limits can prevent identification from finishing.

Statistics report attempt reasons, local probe errors, per-host timeouts,
peak connection slots, cumulative gate waiting/probe time, mean successful TCP
attempt duration, and service inspection statuses. TCP duration includes socket
handling; it is not a pure network RTT measurement. Retries count separately.
Timing totals can exceed wall-clock duration because probes run concurrently.

NDJSON adds `summary.diagnostics` and the full effective settings. Host detail
is limited to 256 addresses; additional attempts still appear in totals and
`unattributed_attempts`. Reason counters have at most 16 keys, including `other`.
Statistics are absent unless requested. Console statistics show selected settings;
use NDJSON for the complete configuration snapshot.

Compare the same resolved IP and ports while changing one setting at a time.
A timeout can reflect filtering, loss, a silent service, or connection pressure;
statistics alone cannot distinguish them. The default ports, timeout, rate,
and port states are unchanged. No automatic rate adaptation is enabled.

YAML keys are `tcp.host_rate`, `tcp.host_concurrency`, and `output.stats`.
Environment equivalents are `NETGO_TCP_HOST_RATE`, `NETGO_TCP_HOST_CONCURRENCY`,
and `NETGO_OUTPUT_STATS`, with the usual [configuration priority](usage.md#configuration).
