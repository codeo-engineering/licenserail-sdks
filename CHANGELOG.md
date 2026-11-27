# Changelog

One version per working day with changes. All packages share the version; only the packages that changed are published, the
others stay on their last published version. The day's last commit carries the tag `vX.Y.Z` (Go: `go/vX.Y.Z`, CLI: `cli/vX.Y.Z`
when they are released).

## 0.1.1 — 2026-11-27

Published: `@codeo-engineering/licenserail-embedded`, `@codeo-engineering/licenserail-youtrack`.

- Keyless trials from apps inside a host send the installation (`host: {instanceId, baseUrls}`); `startTrial(keyId, host)` in
  licenserail-embedded. The API now starts a YouTrack trial only for an instance that confirms its id at its address, so
  YouTrack apps need this version for trials (license keys work with 0.1.0 too).
- licenserail-youtrack: the license page passes the instance's address; the trial card says the instance must be reachable from
  the internet.

## 0.1.0 — 2026-11-26

First release: npm (`@codeo-engineering/licenserail`, `-embedded`, `-youtrack`), PyPI, crates.io, NuGet, Maven Central, Go
(`go/v0.1.0`), C++ (`v0.1.0`). The CLI release is a draft. Built from 2026-11-19:

- SDKs for .NET, TypeScript, Python, Go, Rust, Java, Swift, C++ (with a C ABI) and PHP on shared test vectors; the licenserail CLI.
- licenserail-embedded (client core for apps inside a host platform) and licenserail-youtrack.
- Devices that can't be identified get a clear error and take no seat.
- Release workflow started by hand, end-to-end tests against a real API, NuGet trusted publishing.
