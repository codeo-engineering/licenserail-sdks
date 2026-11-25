# LicenseRail (.NET)

Client SDK for [LicenseRail](https://licenserail.com) licensing. MIT.

```sh
dotnet add package LicenseRail
```

```csharp
using LicenseRail;

using var client = new LicenseClient(new LicenseClientOptions
{
    ServerUrl = new Uri("https://api.licenserail.com"),
    Vendor = "ten_6f1a7e2c3b4d4e5f8a9b0c1d2e3f4a5b",
    Product = "my-app",
    AppVersion = "1.0.0",
    PublicKeyPem = File.ReadAllText("public-key.pem"),
});

LicenseState state = await client.CheckAsync();       // offline check, refreshed online when due
if (!state.IsValid)
{
    ActivationResult r = await client.ActivateAsync(licenseKey);
    Console.WriteLine(r.Message);
}
bool canExport = client.Current.License?.HasFeature("export") == true;
// await client.DeactivateAsync();  frees the seat
```

- `check()` on every start: offline verification; online refresh when the token is due, or when only the server can clear the
  state (expired, suspended, offline too long, clock problems).
- `activate(key)` on the license screen; floating licenses are checked out and kept alive automatically where the platform allows.
- `deactivate()` frees the seat (needs internet).
- On `license_not_found`, `license_suspended`, `license_revoked`, `license_expired`, `activation_revoked`, `wrong_machine` and
  `invalid_token` the local license is removed; other errors (network, `402`) keep it.
- Get the public key with `licenserail public-key --pem` or `licenserail init dotnet`.

Source: [licenserail-sdks](https://github.com/codeo-engineering/licenserail-sdks) (`dotnet/`). Tests (shared vectors in `../test-vectors`): `dotnet test LicenseRail.slnx`.
