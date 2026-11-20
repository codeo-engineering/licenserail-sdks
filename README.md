# LicenseRail SDKs

Client SDKs for [LicenseRail](https://licenserail.com) licensing (working name), the CLI and the shared test vectors. MIT licensed.

| Language | Folder | Package (planned) | Tested |
|---|---|---|---|
| .NET | `dotnet/` | NuGet `LicenseRail` | vectors + example against a local API |
| TypeScript / Node / Electron | `typescript/` | npm `licenserail` | vectors + example against a local API |
| Python | `python/` | PyPI `licenserail` | vectors |
| Go | `go/` | `github.com/codeo-engineering/licenserail-sdks/go` | vectors (CI) |
| Rust | `rust/` | crates.io `licenserail` | vectors (CI) |
| Java / Kotlin / Android | `java/` | Maven `com.licenserail:licenserail` | vectors |
| Swift (macOS, iOS) | `swift/` | Swift Package | vectors (CI, macOS runner) |
| C++ + C ABI | `cpp/` | CMake (mbedTLS, libcurl or your own transport) | vectors (CI) |
| PHP / WordPress | `php/` | Packagist `licenserail/licenserail` | vectors (CI) |

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
