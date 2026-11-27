# Releasing

`.github/workflows/release.yml` (Actions → Release → Run workflow) is started by hand: choose the package and the version.

- Without **publish** it runs all SDK tests and the end-to-end tests, builds the package and keeps it as an artifact. Nothing is published.
- With **publish** (from `main` only) it does the same and then publishes. A published version can't be replaced.

**npm packages** are under the Codeo organization: `@codeo-engineering/licenserail`, `@codeo-engineering/licenserail-embedded`
and `@codeo-engineering/licenserail-youtrack`. The unscoped `licenserail`, `licenserail-embedded` and `licenserail-youtrack` 0.1.0
(2026-11-25, from a personal account) were a mistake and are removed. Nothing else is published yet.

All packages share one version. `node tools/check-versions.mjs 0.1.0` lists the places that differ; the workflow runs it too.

## Once, before the first release

Accounts are opened by a person on behalf of Codeo Solutions, with two-factor authentication. Put the secrets into the GitHub
environment `release` of this repository (Settings → Environments), with a required reviewer if the plan allows it.

| Package | Account / setup | Secret in `release` |
|---|---|---|
| npm `@codeo-engineering/licenserail`, `-embedded`, `-youtrack` | npmjs.com, organization `codeo-engineering` (the scope puts the packages there); granular token: **Bypass two-factor authentication** checked (off by default; without it npm answers `EOTP`), Read and write (publish and stage), All packages | `NPM_TOKEN` |
| NuGet `LicenseRail` | nuget.org; the account's user name in the repository variable `NUGET_USER`; Trusted Publishing policy: owner `codeo-engineering`, repository `licenserail-sdks`, workflow `release.yml`, environment `release`, push new packages, `LicenseRail*` (a private repository keeps it temporary for 7 days until the first publish) | none |
| PyPI `licenserail` | pypi.org; pending trusted publisher: owner `codeo-engineering`, repository `licenserail-sdks`, workflow `release.yml`, environment `release` | none |
| crates.io `licenserail` | crates.io (GitHub sign-in, verified email); token with publish-new and publish-update | `CARGO_REGISTRY_TOKEN` |
| Maven `com.licenserail:licenserail` | central.sonatype.com; namespace `com.licenserail` verified by a DNS TXT record; user token; GPG key, public part on a key server | `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD`, `MAVEN_GPG_PRIVATE_KEY`, `MAVEN_GPG_PASSPHRASE` |
| Swift | public repository `licenserail-swift`; deploy key with write access | `SWIFT_DEPLOY_KEY` |
| Packagist `licenserail/licenserail` | public repository `licenserail-php`; deploy key with write access; submit the repository on packagist.org after the first release | `PHP_DEPLOY_KEY` |
| Go, C++, CLI | this repository must be public | none |

npm removes direct publishing with such tokens in January 2027. Before the next npm release set up trusted publishing for the three
packages (they exist now); the workflow then needs no token.

The mirror repositories `licenserail-swift` and `licenserail-php` start empty; the workflow fills them.

The end-to-end tests read the API image: give this repository read access to the package `licenserail-api` (GitHub → package →
Package settings → Manage Actions access, role Read). Done on 2026-11-25.

A run takes about 25 minutes. After a failed publish step use "Re-run failed jobs": the tests are not repeated. A new npm package
shows `0.0.0-stage` for about a minute before its version appears. Start at most two releases at once: GitHub keeps one waiting
run and cancels an older waiting one.

## Order

1. Check that every package name is still free, and make this repository public.
2. Run every package once without publish and look at the artifacts.
3. Publish `npm-licenserail`, `npm-embedded`, `npm-youtrack`, `nuget`, `pypi`, `crates`.
4. `maven`: the workflow uploads and validates; press Publish on central.sonatype.com.
5. `go` (tag `go/v0.1.0`), `cpp` (tag `v0.1.0`), `swift`, `php`.
6. `cli`: the workflow makes a draft GitHub release; publishing the draft creates the tag `cli/v0.1.0`.
7. Install each package in an empty project with the command from the docs.

The CLI's program lives in `cli/cmd/licenserail`, so `go install .../licenserail-sdks/cli/cmd/licenserail@latest` installs a
program called `licenserail` (Go names it after the last folder).

## A new version

Every working day with changes is a new version (patch while on 0.x for fixes and small additions). Add the day to
`CHANGELOG.md` with the packages that were published, then tag the day's last commit `vX.Y.Z`.


Change the version everywhere (the check lists the places; also `npm install --package-lock-only` in the three npm folders),
merge to `main`, then run the workflow per package.
