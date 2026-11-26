# LicenseRail SDKs

Client SDKs for [LicenseRail](https://licenserail.com) licensing, the CLI and the shared test vectors. MIT licensed.

| Language | Folder | Package | Tested |
|---|---|---|---|
| .NET | `dotnet/` | NuGet `LicenseRail` | vectors + example against a local API |
| TypeScript / Node / Electron | `typescript/` | npm [`@codeo-engineering/licenserail`](https://www.npmjs.com/package/@codeo-engineering/licenserail) | vectors + example against a local API |
| Python | `python/` | PyPI `licenserail` | vectors |
| Go | `go/` | `github.com/codeo-engineering/licenserail-sdks/go` | vectors (CI) |
| Rust | `rust/` | crates.io `licenserail` | vectors (CI) |
| Java / Kotlin / Android | `java/` | Maven `com.licenserail:licenserail` | vectors |
| Swift (macOS, iOS) | `swift/` | Swift Package | vectors (CI, macOS runner) |
| C++ + C ABI | `cpp/` | CMake (mbedTLS, libcurl or your own transport) | vectors (CI) |
| PHP / WordPress | `php/` | Packagist `licenserail/licenserail` | vectors (CI) |
| Apps inside a host (YouTrack apps, browser extensions, web apps) | `embedded/` | npm [`@codeo-engineering/licenserail-embedded`](https://www.npmjs.com/package/@codeo-engineering/licenserail-embedded) | vectors, Wycheproof, sandbox (CI) |
| YouTrack apps (adapter, License page, CLI) | `youtrack/` | npm [`@codeo-engineering/licenserail-youtrack`](https://www.npmjs.com/package/@codeo-engineering/licenserail-youtrack) | fake YouTrack runtime (CI) |

Every SDK does the same things: verify the signed license file offline with the environment's public key (ECDSA P-256,
IEEE P1363 signatures), hash the device fingerprint, evaluate offline (expiry, offline grace, clock rollback, suspension),
activate, refresh when due, deactivate, and floating leases with heartbeats. Server-side management clients (API key
required, never in an app) are in the .NET, TypeScript, Python packages; the others call `/api/v2` directly (see
`openapi.json` of the API).

## Test vectors

`test-vectors/` holds `tokens.json`, `fingerprint.json`, `match.json` and `evaluate.json`, generated from the reference
implementation by `tools/vectorgen` (needs `licenserail-api` checked out next to this repo as `../api`):

```
dotnet run --project tools/vectorgen -- test-vectors
```

CI (`.github/workflows/sdks.yml`) runs every SDK against them.

## End-to-end tests

`e2e/` installs every SDK's built package into an empty project and runs the same scenarios against a real API with an empty
database (activation, offline use, seats, refresh, suspension, revocation, expiry, copied and changed files, clock changes,
floating licenses, broken servers and proxies). CI (`.github/workflows/e2e.yml`) runs them on Linux, Windows and macOS; a
release needs them to pass. Locally:

```
e2e/start-api.sh <published API folder> <work folder>
E2E_MAIL=<work folder>/mail node e2e/run.mjs typescript go
```

Every SDK also passes the end-to-end tests above. Releases: [RELEASING.md](RELEASING.md).
