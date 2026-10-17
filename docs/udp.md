# UDP scanning

```sh
scan 127.0.0.1 --transport udp -p 53,123 --format ndjson
scan 127.0.0.1 --transport udp -p 5353 --udp-probe dns --retries 1
scan 192.0.2.0/28 --transport udp -p 53,123,161 --udp-host-rate 10
```

One transport is selected per run. TCP remains the default. The common port
list applies to both transports, so supply UDP ports explicitly. No root,
administrator privileges, libpcap, or raw sockets are required by this backend.
`--service` is TCP-only; UDP protocol matching is part of the initial probe.

## Payloads and matching

Every attempt opens a fresh connected UDP socket and sends exactly one datagram.
The socket accepts replies only from the selected remote address/port. Retries
use new sockets and new protocol transaction values. No TCP fallback is used.

| `--udp-probe` | Request | Accepted reply |
| --- | --- | --- |
| `auto` | DNS on 53, NTP on 123, empty elsewhere | Corresponding rule below |
| `dns` | Nonrecursive `. IN NS` query, random 16-bit ID, no EDNS | Parsed DNS response with matching ID, query opcode, and exactly the same question |
| `ntp` | 48-byte NTP v4 client request with current transmit seconds and random fraction | At least 48 bytes, server mode, version 3/4, stratum 0–16, matching originate timestamp |
| `empty` | Zero-length datagram | Any datagram from the connected peer, including a zero-length reply |

Valid DNS error replies such as REFUSED still prove that the server answered.
NTP stratum-zero kiss-of-death replies also prove a response and retain the
four-byte code as evidence; they are not retried. Protocol matches add `dns` or
`ntp` service evidence without guessing software/version. DNS decoding uses
miekg/dns. Generic replies do not identify a protocol and have no transaction
nonce beyond the connected socket's endpoint filtering.

## States and errors

| Observation | State | Reason |
| --- | --- | --- |
| Matching accepted datagram | `open` | `udp_response` |
| Socket reports port unreachable after send attempt | `closed` | `port_unreachable` |
| No accepted reply before deadline, after a successful send | `open|filtered` | `timeout` |
| Network/host unreachable reported by the OS | `unknown` | `network_unreachable` / `host_unreachable` |
| 64 malformed, unmatched, or oversized replies | `unknown` | `response_limit` |

Only timeout results are retried, up to `--retries` additional attempts. Packet
loss, firewall drops, protocol mismatch, ignored requests, and ICMP rate limiting
can all produce silence; silence is never proof of a closed or filtered port.
Local socket setup/send deadlines, resource exhaustion, permissions failures,
and unexpected I/O errors fail the command instead of becoming port evidence.
Access-denied errors can originate from local policy or network rejection; this
backend does not classify them as confirmed filtering.

This implementation interprets kernel-delivered socket errors rather than
capturing ICMP packets. Unix ECONNREFUSED is mapped to port unreachable. On
Windows, SIO_UDP_CONNRESET is enabled on each socket because Go disables these
notifications by default; UDP WSAECONNRESET/WSAECONNREFUSED are mapped to closed.
Other ICMP type/code distinctions and router identity are not decoded. Platforms
or paths that suppress these notifications can leave a closed port ambiguous.
The `filtered` summary counter is reserved for confirmed future filtering evidence.

References: [Linux UDP error behavior](https://man7.org/linux/man-pages/man7/udp.7.html),
[Windows UDP receive errors](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_wsarecvmsg),
[NTP packet specification](https://www.rfc-editor.org/rfc/rfc5905).

## Limits and output

- `--timeout` covers socket setup, send, and reply processing for each attempt;
  rate waiting happens before it. Cancellation closes in-flight sockets.
- `--rate` controls all probe starts; `--udp-host-rate` additionally paces a host,
  including retries. Both have burst size one and consume tokens together at
  dispatch time. The host table has 1024 hash buckets with a per-run random seed;
  colliding hosts share a conservative budget, which can reduce throughput.
  The table never grows with the CIDR size. Waiting workers do not hold its lock.
- `--udp-max-bytes` defaults to 4096 and accepts 48–65535. Oversized datagrams
  are discarded, including Windows message-too-large errors. They are not
  partially parsed or accepted. A buffer of the cap plus one byte detects excess.
- At most 64 rejected datagrams are processed before returning `response_limit`;
  the attempt deadline is unchanged while processing noise.
- Results retain the final attempt's UDP probe name, matched reply byte count,
  and ignored/oversized reply counters. Reply bodies are not stored. `attempts`
  and summary attempt counts include retries, but not DNS preflight resolution.
- Summaries distinguish open, closed, open|filtered, filtered, and unknown.
  Completed scans can include ambiguous results and still exit successfully.

The TCP identification options, TLS SNI, and banner rules do not apply to UDP.
The TCP target-expansion rules still apply, including network/broadcast addresses
in CIDRs. Sending to a broadcast address can be denied by OS policy; this backend
does not enable broadcast sending or multicast membership.
