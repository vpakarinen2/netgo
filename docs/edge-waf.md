# Edge and WAF identification

Edge observations are included automatically when `--service` parses an HTTP
response. No extra requests or connections are added:

```sh
./bin/scan localhost --top-ports 100 --service --open-only
```

Console results show edge and WAF observations in aligned columns on the port row:

```text
EDGE                  WAF
cloudflare [high]     unknown
```

`-` means no match or no collected HTTP headers. `unknown/challenge` means a
Cloudflare challenge was observed while WAF status remains unknown. A `?`
marks conflicting or unmatched headers. NDJSON retains full evidence, challenge
providers, and warning codes. Long console cells are shortened with `...`.
Product/version share one column; per-port attempts remain available in NDJSON.

## What is recognized

| Observation | Evidence used |
| --- | --- |
| Cloudflare CDN | `Server: cloudflare`, `Cf-Ray`, or the challenge header |
| CloudFront CDN | `Server: CloudFront`, `X-Amz-Cf-Id`, `X-Amz-Cf-Pop`, or a CloudFront-specific `X-Cache` value |
| Varnish cache | `Server: Varnish`, `Via: 1.1 varnish`, or numeric `X-Varnish` IDs |
| Cloudflare challenge | `Cf-Mitigated: challenge`; reported separately from WAF status |
| AWS WAF signal | `X-Amzn-Waf-Action: challenge` with HTTP 202, or `captcha` with HTTP 405 |

Confidence describes the signature match: `low` for a weak single signal,
`medium` for an explicit Server product, and `high` for multiple supporting
signals. Cloudflare challenges use `medium`; matching AWS action/status pairs
use `high`. Confidence is not authentication or a probability of protection.

## Understanding WAF status

- `unknown`: no supported WAF-specific signature matched. This includes ordinary
  Cloudflare/CloudFront responses and generic 403 or 429.
- `signal_observed`: a supported AWS WAF action/status pair was present.

A CDN or cache match does not establish WAF configuration. A Cloudflare challenge
can come from different security features. Even a WAF-specific response only
describes the observed request; it does not establish coverage or effectiveness.
Headers can be hidden, changed, or imitated, so absence is inconclusive.

Collected HTTP/1.1 and HTTP/2 headers use the same signatures. Generic TLS, SSH,
UDP, and HTTPS without successfully collected headers have no web observations. The scanner
does not fetch challenge pages, solve challenges, follow redirects, or send
additional detection probes. `--service-active=false` can identify web headers
only if the server sends them without a request.

## Evidence and conflicting responses

NDJSON adds `service.web` with `edge`, `waf`, optional `challenges`, and optional
`warnings`. Detections contain provider, kind, confidence, and evidence.
Web evidence retains normalized signature values and header presence, not raw
trace IDs or cookie values. Metadata is bounded by the fixed signature set.

Multiple providers can be reported because responses may pass through layers.
Conflicting Server products produce `conflicting_server_headers` and downgrade
edge confidence. Repeated or unmatched AWS action headers keep WAF status unknown
and add `unmatched_aws_waf_action`. No winner or network topology is inferred.

## Signature references

- [Cloudflare HTTP headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/)
- [Cloudflare challenge response header](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/)
- [CloudFront request/response behavior](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html)
- [AWS WAF challenge/CAPTCHA responses](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html)
- [Varnish response header examples](https://www.varnish-software.com/developers/tutorials/logging-cache-hits-misses-varnish/)
