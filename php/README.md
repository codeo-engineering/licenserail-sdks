# LicenseRail (PHP / WordPress)

Client SDK for [LicenseRail](https://licenserail.com) licensing. MIT.

```sh
composer require licenserail/licenserail
```

```php
use LicenseRail\LicenseClient;

$client = new LicenseClient(['serverUrl' => 'https://api.licenserail.com', 'vendor' => 'ten_6f1a7e2c3b4d4e5f8a9b0c1d2e3f4a5b', 'product' => 'my-plugin', 'publicKeyPem' => $pem]);
$result = $client->check();                 // per site: site host + install id
if (!$result->isValid()) { echo $client->activate($licenseKey)->message; }
$canExport = $client->license()?->hasFeature('export');
```

- `check()` on every start: offline verification; online refresh when the token is due, or when only the server can clear the
  state (expired, suspended, offline too long, clock problems).
- `activate(key)` on the license screen; floating licenses are checked out and kept alive automatically where the platform allows.
- `deactivate()` frees the seat (needs internet).
- On `license_not_found`, `license_suspended`, `license_revoked`, `license_expired`, `activation_revoked`, `wrong_machine` and
  `invalid_token` the local license is removed; other errors (network, `402`) keep it.
- Get the public key with `licenserail public-key --pem` or `licenserail init php`.

Developed in [licenserail-sdks](https://github.com/codeo-engineering/licenserail-sdks) (`php/`); this code is copied from there on every release, send changes there.
