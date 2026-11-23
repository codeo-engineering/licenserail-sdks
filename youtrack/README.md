# licenserail-youtrack

Sell your YouTrack app with LicenseRail license keys: activation per YouTrack instance, keyless trials, per-user limits
and a ready **License** page in the administration menu. Built on [`licenserail-embedded`](../embedded); everything that
ends up in your app is readable JavaScript, as JetBrains Marketplace requires.

Needs YouTrack 2026.2 or later (async HTTP).

## Add it to your app

```sh
npx licenserail-youtrack add ./my-app \
  --vendor ten_... --product my-app --key-id <key id> --public-key public-key.pem
```

Take the values from the LicenseRail dashboard (Developers → Integration code). The command:

- copies `licenserail-core.js`, `licenserail.js`, `licenserail-license.js` and the `widgets/licenserail-license` page,
- writes `licenserail-config.js` (once; none of its values is a secret),
- adds the secret `licenseKey` setting to `settings.json`, the storage fields to `entity-extensions.json`, and the License
  page to `manifest.json` (and raises `minYouTrackVersion` to 2026.2).

Run it again to update the LicenseRail files. For apps built with Vite, pass `--backend src` (the folder that holds your
backend `.js` files).

## Check the license in your handlers

```js
const licenserail = require('./licenserail');

exports.httpHandler = {
  endpoints: [{
    method: 'GET', path: 'summary',
    handle(ctx) {
      const license = licenserail.check(ctx);          // offline: no network call
      if (!license.valid) { ctx.response.statusCode = 402; ctx.response.json({ error: 'license_required' }); return; }
      if (licenserail.hasFeature(ctx, 'advanced-reports')) { /* ... */ }
    },
  }],
  asyncFunctions: licenserail.asyncFunctions,            // lets check() schedule the daily refresh
};
```

`check(ctx)` returns `{ valid, status, summary }`; `summary` has `isTrial`, `expiresAt`, `entitlements`, `metadata`,
`maxHostUsers`, `hostUserPolicy` and `hostUsersOverLimit`. The License page and its endpoints are for administrators only
and never return the key or the token.

## How it works

- **Installation:** the License page reads the instance id (`/api/config` → `uuid`) and the backend licenses that instance.
  The backend can't read the id itself, so activation and trials start once an administrator has opened the page. If the id
  ever changes (a move or a restore), activate again and release the old instance in LicenseRail.
- **License key:** the administrator enters it in the app's settings (a secret setting). YouTrack sends it only as
  `Authorization: Bearer`; scripts never see it.
- **Activation, trial, refresh, release:** async HTTP (`postAsync`); the answer is stored in app storage and the page
  shows the result. The license is refreshed daily; network errors keep it working until its offline period ends.
- **Users:** the instance's user count is sent with activations and refreshes; the license decides (block, warn or report).
- **Trials:** one per YouTrack instance, reinstalls included; no key ships with the app.

## Marketplace listing

JetBrains asks you to disclose calls to a license server. Suggested text: *"The app contacts LicenseRail
(api.licenserail.com), operated by Codeo Solutions Limited, to activate and verify its license. It sends the license key,
the app version, the number of users of this YouTrack instance, and a hashed identifier of the instance."* Link your
privacy policy, and use a custom license (EULA) rather than an open-source one; see the end-user license template in the
LicenseRail docs.

## Develop and test

`npm test` builds `dist/app-files` and runs the app files against a fake YouTrack runtime (async HTTP, storage, settings,
permissions), including a run without web or Node globals. `example/` is a minimal app; add LicenseRail to it with the
command above.
