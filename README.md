# Device Truth Probe

Neutral measurement probe for real Apple runtime fingerprinting.

## What this does

Runs on GitHub Actions macOS runners (free tier, public repo) and collects browser fingerprint samples from:
- **macOS Safari** (real Apple Silicon)
- **iOS Simulator** (real iOS runtime via simctl)

Every sample optionally carries measured transport evidence captured by `tls-trap.js`
(`samples[i].transport`): the raw TLS ClientHello digest (`tls`), the HTTP/2
SETTINGS/frame sequence (`http2`), and the HTTP/1.1 header order (`http1`). The trap
suite (hello-sniffer + Node TLS sessions + export server) listens on
`TRUTH_PORT+10 … TRUTH_PORT+13`; its self-signed root is installed into the macOS
System keychain with `security add-trusted-cert` so real Safari completes TLS.

## Fields collected

`uuid`, `lane`, `model`, `os`, `browser`, `ua`, `platform`, `screen`, `viewport`, `hw`, `webgl`, `fonts`, `timeline`, `webkit`, `harvestedAt`, plus optional `transport.tls`, `transport.http2`, `transport.http1`.

## How to use

1. Fork or clone this repo
2. The active workflow lives at `.github/workflows/probe.yml`
3. Trigger via `repository_dispatch`:
   ```
   POST /repos/{owner}/{repo}/dispatches
   { "event_type": "truth-probe", "client_payload": { "lane": "macos", "sample": "t<ts>-macos" } }
   ```
4. Samples are committed to branch `samples-<lane>` under `samples/`

## Label

This probe produces `hosted-truth` samples (hosted Apple runtime, not physical device). It never claims `measured-population`.

## License

Public domain. No warranties. Use at your own risk.