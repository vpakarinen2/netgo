# Service identification

Add `--service` to identify services on open TCP ports:

```sh
./bin/scan localhost -p 22,80,443 --service
```

Netgo recognizes HTTP, HTTPS, SSH, and TLS. Detection uses responses and
negotiated protocols; an open port alone does not identify its service.
[UDP detection](udp.md) is automatic and does not use `--service`.
Parsed HTTP responses also include [passive edge and WAF observations](edge-waf.md),
with evidence and confidence. CDN identity alone does not establish WAF protection.

## How it works

1. Read a server banner, such as an SSH greeting.
2. If the server is silent, try TLS and inspect its certificate.
3. Try an HTTP `HEAD /` request over TLS, or plaintext if TLS fails.

An unrecognized nonempty banner is saved without further probing. HTTPS uses
HTTP/1.1 or HTTP/2 as negotiated by TLS. Both collect headers with one `HEAD /`
request on the existing TLS connection; redirects are not followed.

Identification can open up to three extra connections per open port. These share
`--rate` with port scans. Identification failures leave the port's `open` result
unchanged, and there are no service retries.
`--tcp-host-rate` and `--tcp-host-concurrency` also apply to these connections.

## Options

| Option | Purpose | Default |
| --- | --- | --- |
| `--service-active=false` | Only read banners; skip TLS and HTTP requests | Active probes enabled |
| `--service-timeout` | Total time per inspection, including rate waits | `3s` |
| `--service-concurrency` | Concurrent inspections | `16` |
| `--service-max-bytes` | Banner/HTTP byte limit; HTTP/2 limits decoded headers including field overhead | `8192` |
| `--sni` | Override the TLS server name and HTTP Host | Target hostname |

```sh
./bin/scan localhost -p 22 --service --service-active=false
./bin/scan 127.0.0.1 -p 8443 --service --sni example.test
```

Low rate limits can use up the inspection timeout before probing finishes.
Individual active stages are capped at one second.

## Understanding TLS results

Results can include TLS version, cipher, ALPN, certificate fingerprint, validity
dates, and hostname matching. Hostnames are used for SNI; IP targets omit SNI
unless `--sni` is supplied. The override keeps connections on the original IP.

**Certificate trust is not verified.** Self-signed, expired, and mismatched
certificates can be inspected. `certificate_verification` is `not_performed`;
hostname and date checks do not establish trust. Software versions are server claims.

TLS inspection currently supports TLS 1.2 and 1.3. Servers that only support
TLS 1.0 or 1.1 cannot be identified through a TLS handshake.

TLS input and certificate details are size-limited. Very large certificate chains
can fail inspection, and certificate name lists may be truncated. STARTTLS,
HTTP/3 and external signatures are unsupported. If HTTP/2 headers fail or exceed
the limit, HTTPS and certificate evidence are kept with the inspection error.
See the [output format](output-schema.md) for result fields.
