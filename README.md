# Device Truth Probe

Neutral measurement probe for real Apple runtime fingerprinting.

## What this does

Runs on GitHub Actions macOS runners (free tier, public repo) and collects browser fingerprint samples from:
- **macOS Safari** (real Apple Silicon)
- **iOS Simulator** (real iOS runtime via simctl)

## Fields collected

`uuid`, `lane`, `model`, `os`, `browser`, `ua`, `platform`, `screen`, `viewport`, `hw`, `webgl`, `fonts`, `timeline`, `webkit`, `harvestedAt`

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