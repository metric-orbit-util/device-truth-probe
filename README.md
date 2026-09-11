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
2. Create a Classic PAT with `public_repo` + `workflow`
3. Add the token as a repo secret named `TRUTH_TOKEN`
4. Trigger via `repository_dispatch` event `truth-probe` or manual dispatch

## Label

This probe produces `hosted-truth` samples (hosted Apple runtime, not physical device). It never claims `measured-population`.

## License

Public domain. No warranties. Use at your own risk.