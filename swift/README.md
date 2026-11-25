# LicenseRail (Swift: macOS, iOS)

Client SDK for [LicenseRail](https://licenserail.com) licensing. MIT.

```swift
.package(url: "https://github.com/codeo-engineering/licenserail-swift", from: "0.1.0")
```

```swift
let client = try LicenseClient(options: .init(serverURL: URL(string: "https://api.licenserail.com")!, vendor: "ten_6f1a7e2c3b4d4e5f8a9b0c1d2e3f4a5b", product: "my-app",
                                              appVersion: "1.0.0", publicKeyPEM: publicKey))
let result = await client.check()           // offline check, refreshed online when due
if !result.isValid { print(await client.activate(licenseKey: key).message) }
let canExport = client.license?.hasFeature("export") == true
```

- `check()` on every start: offline verification; online refresh when the token is due, or when only the server can clear the
  state (expired, suspended, offline too long, clock problems).
- `activate(key)` on the license screen; floating licenses are checked out and kept alive automatically where the platform allows.
- `deactivate()` frees the seat (needs internet).
- On `license_not_found`, `license_suspended`, `license_revoked`, `license_expired`, `activation_revoked`, `wrong_machine` and
  `invalid_token` the local license is removed; other errors (network, `402`) keep it.
- Get the public key with `licenserail public-key --pem` or `licenserail init swift`.

Developed in [licenserail-sdks](https://github.com/codeo-engineering/licenserail-sdks) (`swift/`); this code is copied from there on every release, send changes there.
