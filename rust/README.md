# LicenseRail (Rust)

Client SDK for [LicenseRail](https://licenserail.com) licensing. MIT.

```sh
cargo add licenserail
```

```rust,ignore
use licenserail::{LicenseClient, Options};

let mut client = LicenseClient::new(Options {
    server_url: "https://api.licenserail.com".into(),
    vendor: "ten_6f1a7e2c3b4d4e5f8a9b0c1d2e3f4a5b".into(),
    product: "my-app".into(),
    public_key_pem: PUBLIC_KEY.into(),
    ..Options::default()
})?;
if !client.check().is_valid() {
    println!("{}", client.activate(&license_key, None).message);
}
let can_export = client.license().map_or(false, |l| l.has_feature("export"));
```

- `check()` on every start: offline verification; online refresh when the token is due, or when only the server can clear the
  state (expired, suspended, offline too long, clock problems).
- `activate(key)` on the license screen; floating licenses are checked out and kept alive automatically where the platform allows.
- `deactivate()` frees the seat (needs internet).
- On `license_not_found`, `license_suspended`, `license_revoked`, `license_expired`, `activation_revoked`, `wrong_machine` and
  `invalid_token` the local license is removed; other errors (network, `402`) keep it.
- Get the public key with `licenserail public-key --pem` or `licenserail init rust`.

Source: [licenserail-sdks](https://github.com/codeo-engineering/licenserail-sdks) (`rust/`). Tests (shared vectors in `../test-vectors`): `cargo test`.
