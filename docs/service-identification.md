# Service identification

This guide describes TCP inspection. [UDP protocol matching](udp.md) is built
into its probes and does not use the `--service` stage.

Enable with `--service`. Default TCP scans send no service payloads. Inspection
is best-effort evidence collection after a port was observed open; failures do
not change its state, observation timestamp, duration, or port attempt count.

## Probe sequence

1. Open a new connection and read a banner. The read window is the smaller of
   200 ms and one quarter of the total inspection budget, bounded by the overall
   deadline. SSH banners and complete HTTP/1 headers are matched by embedded YAML
   definitions. A nonempty unrecognized banner is retained without further probes.
2. If silent and active mode is enabled, open a new connection and send a TLS
   ClientHello. Offer ALPN `h2` and `http/1.1`; allow TLS 1.2 and 1.3. Retain
   protocol/cipher, selected ALPN, SNI, and leaf certificate observations.
3. If TLS succeeds and selects `h2`, record HTTPS with ALPN evidence and send no
   application request. Otherwise, send `HEAD / HTTP/1.1` on the TLS connection.
   A valid HTTP response identifies HTTPS; failed HTTP identification preserves
   the generic TLS identity and certificate information.
4. If TLS fails, open a final plaintext connection and send `HEAD / HTTP/1.1`.
   Match a complete HTTP/1 header block. No redirects are followed and no body
   is deliberately read; a bounded final read may include a body prefix.

TLS and plaintext HTTP stages each have a deadline of the smaller of one second
and one third of `--service-timeout`. The overall per-port budget also bounds
the first dial, rate waits, and all stages. No retry loops are used. Increasing
the total budget does not increase the one-second active-stage ceilings.

`--service-active=false` stops after banner acquisition and sends no application
payload. It still opens one additional TCP connection. Client-first protocols
usually time out in this mode. The server-name override and other service
settings take effect only when service identification is enabled.

## Bounds and scheduling

- Default inspection concurrency is 16, configurable from 1 to 256. Port workers
  remain independent; bounded queues propagate backpressure when saturated.
- Every dial waits on the same `--rate` limiter as port attempts. At most three
  additional dials occur per open port. Rate waits consume the inspection budget.
- Default banner/HTTP byte cap is 8192, configurable from 256 to 65536 per read
  phase. Unknown data is retained up to this cap; invalid UTF-8 uses base64.
- TLS wire input is capped at 256 KiB across handshake and any encrypted HTTP
  response, independently of the application read cap. This can reject very
  large certificate chains. Peer certificate chains are not retained in results.
- Leaf subject/issuer strings are capped at 512 bytes, serial at 128 bytes, and
  error strings at 512 bytes. At most 32 DNS SANs (253 bytes each) and 32 IP SANs
  are retained; `names_omitted` counts additional names.
- Sockets have deadlines and close when the inspection context is canceled.
  Completed port results still flow to output when identification is canceled.

## TLS interpretation

Inspection accepts untrusted certificates to collect evidence from self-signed,
expired, and mismatched endpoints. It does not build or validate a trust chain,
fetch issuers, perform revocation checks, or send client certificates.
`certificate_verification` is always `not_performed`. Offline hostname matching
and current-time validity are separate observations, not proof of trust.

For hostname targets, SNI and HTTP Host use the retained hostname. For an IP
target, SNI is omitted and hostname verification checks the IP SAN. `--sni`
accepts a DNS hostname and overrides SNI, certificate reference name, and HTTP
Host, while dialing the original resolved IP. HTTP Host includes the target port.
ALPN `h2` is negotiated protocol evidence; this release does not issue HTTP/2
requests or extract HTTP/2 Server headers.

Useful protocol references: [Go TLS configuration](https://pkg.go.dev/crypto/tls#Config),
[offline certificate hostname checks](https://pkg.go.dev/crypto/x509#Certificate.VerifyHostname),
and [SSH transport identification](https://www.rfc-editor.org/rfc/rfc4253).

## Coverage

HTTP/1.0, HTTP/1.1, HTTPS, SSH identification banners, and generic TLS are covered.
Detection is based on received bytes/negotiated protocol, not port-number hints.
Software versions from Server headers and SSH banners are untrusted claims.
Embedded signatures are built into the binary; external rule loading, STARTTLS,
HTTP/2 application probes, HTTP/3/QUIC, and additional protocols remain future work.
