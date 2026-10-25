# Example Wasm checks

Run `go run ./tools/build-plugins` from the repository root. This builds the example
WASI commands and generates their checksum-pinned `plugin.yaml` manifests.
It also installs bundles into `bin/scripts`, so you can select them by name.

- `tls-expiry`: certificate expiry, with a configurable `days` threshold.
- `tls-hostname`: certificate reference-name mismatch.
- `tls-certificate`: collected leaf certificate information, including healthy certificates.
- `ssh-banner`: a configurable substring in the reported SSH product.

The `fixtures` directory contains offline JSON requests. For example:

```powershell
.\bin\scan.exe scripts test tls-expiry --input .\examples\plugins\fixtures\https.json
```

See the [plugin guide](../../docs/wasm-plugins.md) for live scans, the SDK contract,
limits, and configuration. Generated Wasm modules and manifests are not committed.
