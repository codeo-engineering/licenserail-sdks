# LicenseRail (Java / Kotlin / Android)

Client SDK for [LicenseRail](https://licenserail.com) licensing. MIT.

```kotlin
implementation("com.licenserail:licenserail:0.1.0")
```

```java
LicenseClient client = new LicenseClient(LicenseOptions.builder()
    .serverUrl("https://api.licenserail.com").vendor("ten_6f1a7e2c3b4d4e5f8a9b0c1d2e3f4a5b").product("my-app").publicKeyPem(publicKey).appVersion("1.0.0").build());
var result = client.check();                // offline check, refreshed online when due
if (!result.isValid()) System.out.println(client.activate(licenseKey).message());
boolean canExport = client.license() != null && client.license().hasFeature("export");
// Android: pass .fingerprint(...) with an app-scoped install id hashed by Licensing.hashComponent.
```

- `check()` on every start: offline verification; online refresh when the token is due, or when only the server can clear the
  state (expired, suspended, offline too long, clock problems).
- `activate(key)` on the license screen; floating licenses are checked out and kept alive automatically where the platform allows.
- `deactivate()` frees the seat (needs internet).
- On `license_not_found`, `license_suspended`, `license_revoked`, `license_expired`, `activation_revoked`, `wrong_machine` and
  `invalid_token` the local license is removed; other errors (network, `402`) keep it.
- Get the public key with `licenserail public-key --pem` or `licenserail init java`.

Source: [licenserail-sdks](https://github.com/codeo-engineering/licenserail-sdks) (`java/`). Tests (shared vectors in `../test-vectors`): `mvn test`.
