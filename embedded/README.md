# licenserail-embedded

The LicenseRail client core for apps that run **inside a host platform**: YouTrack apps, browser extensions, web apps,
workers. No dependencies and no Node APIs: it needs ES2020 (BigInt) and nothing else, so it also runs where `TextEncoder`,
`atob` and `crypto.subtle` are missing (YouTrack app backends).

- Offline verification of LicenseRail tokens (ECDSA P-256, IEEE P1363) with a bundled verifier, or WebCrypto when the host has it.
  The bundled verifier passes all 262 Project Wycheproof P1363 cases.
- Installation identity: `installationFingerprint(vendor, product, platform, installationId)` licenses one installation of
  the host (for example a YouTrack instance) instead of a computer.
- Request builders and response reading for activation (key in `Authorization: Bearer` or the body), refresh, deactivation,
  floating leases and keyless trials — no I/O of their own, so callback-style hosts can send them.
- `createLicenseClient(...)`: a ready client for hosts that can await `fetch`.

For YouTrack apps use [`licenserail-youtrack`](../youtrack), which wires this core into app settings, storage, async HTTP
and an admin page.

## Ready client (hosts with fetch)

```js
import { createLicenseClient, installationFingerprint } from 'licenserail-embedded'

const client = createLicenseClient({
  apiUrl: 'https://api.licenserail.com',
  publicKeyPem: PUBLIC_KEY_PEM,                 // from the dashboard; not a secret
  product: 'my-app',
  fingerprint: installationFingerprint(VENDOR_ID, 'my-app', 'chrome', installationId),
  storage: { get: (k) => localStorage.getItem(k), set: (k, v) => localStorage.setItem(k, v), remove: (k) => localStorage.removeItem(k) },
  appVersion: '1.2.0',
})

await client.startTrial(KEY_ID)                 // keyless trial (once per installation)
await client.activate(licenseKey)               // a license key
const { status, summary } = await client.state()   // offline check: 'Valid', 'Expired', 'OfflineTooLong', ...
await client.refresh()                          // when the token asks for it; keeps the license on network errors
await client.deactivate()                       // release this installation
```

`summary` has `isTrial`, `expiresAt`, `entitlements`, `metadata`, `maxHostUsers`, `hostUserPolicy` and
`hostUsersOverLimit`. Pass `hostUsers: () => count` when the license is priced per host user.

## Core functions (any host)

| Function | Purpose |
|---|---|
| `verifyToken(token, pem)` / `verifyTokenAsync(token, pem)` | Signature check; returns the payload or null |
| `evaluate(payload, product, fingerprint, now, lastSeen)` | Offline status, identical in every LicenseRail SDK |
| `summarize(payload, hostUsers?)`, `hasFeature(payload, code)` | What to show and which features to unlock |
| `activateRequest`, `refreshRequest`, `deactivateRequest`, `trialRequest` | `{method, url, headers, body}` to send |
| `readResponse(status, body)` | Token, or an error with `revokesLocalLicense` / `retryLater` |
| `refreshDueAt(payload)` | When to refresh (null for trials) |

Build: `npm run build` writes ES modules to `dist/esm` and CommonJS (for `require()`, e.g. YouTrack apps) to `dist/cjs`.
Tests: `npm test` (shared vectors, Wycheproof, a sandbox without web/Node globals, the client).
