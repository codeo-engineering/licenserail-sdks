# licenserail (Python)

```
pip install licenserail
```

```python
from licenserail import LicenseClient

client = LicenseClient(server_url="https://api.licenserail.com", vendor="ten_6f1a7e2c3b4d4e5f8a9b0c1d2e3f4a5b", product="my-app", public_key_pem=PUBLIC_KEY)
result = client.check()           # offline check, refreshed online when due
if not result.valid:
    client.activate(license_key)
if client.license and client.license.has_feature("export"):
    ...
```

Management API (server side only, needs a secret key): `from licenserail import ManagementClient`.
Tests: `python -m unittest discover -s tests` (runs the shared vectors in `../test-vectors`).
