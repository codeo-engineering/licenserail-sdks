# Releasing

`.github/workflows/release.yml` (Actions → Release → Run workflow) is started by hand: choose the package and the version.

- Without **publish** it runs all SDK tests, builds the package and keeps it as an artifact. Nothing is published.
- With **publish** (from `main` only) it does the same and then publishes. A published version can't be replaced.

All packages share one version. `node tools/check-versions.mjs 0.1.0` lists the places that differ; the workflow runs it too.

## Once, before the first release

Accounts are opened by a person on behalf of Codeo Solutions, with two-factor authentication. Put the secrets into the GitHub
environment `release` of this repository (Settings → Environments), with a required reviewer if the plan allows it.

| Package | Account / setup | Secret in `release` |
|---|---|---|
| npm `licenserail`, `licenserail-embedded`, `licenserail-youtrack` | npmjs.com; granular token with read and write | `NPM_TOKEN` |
| NuGet `LicenseRail` | nuget.org organization; API key with push for `LicenseRail*` | `NUGET_API_KEY` |
| PyPI `licenserail` | pypi.org; pending trusted publisher: owner `codeo-engineering`, repository `licenserail-sdks`, workflow `release.yml`, environment `release` | none |
| crates.io `licenserail` | crates.io (GitHub sign-in, verified email); token with publish-new and publish-update | `CARGO_REGISTRY_TOKEN` |
| Maven `com.licenserail:licenserail` | central.sonatype.com; namespace `com.licenserail` verified by a DNS TXT record; user token; GPG key, public part on a key server | `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD`, `MAVEN_GPG_PRIVATE_KEY`, `MAVEN_GPG_PASSPHRASE` |
| Swift | public repository `licenserail-swift`; deploy key with write access | `SWIFT_DEPLOY_KEY` |
| Packagist `licenserail/licenserail` | public repository `licenserail-php`; deploy key with write access; submit the repository on packagist.org after the first release | `PHP_DEPLOY_KEY` |
| Go, C++, CLI | this repository must be public | none |

The mirror repositories `licenserail-swift` and `licenserail-php` start empty; the workflow fills them.

## Order

1. Check that every package name is still free, and make this repository public.
2. Run every package once without publish and look at the artifacts.
3. Publish `npm-licenserail`, `npm-embedded`, `npm-youtrack`, `nuget`, `pypi`, `crates`.
4. `maven`: the workflow uploads and validates; press Publish on central.sonatype.com.
5. `go` (tag `go/v0.1.0`), `cpp` (tag `v0.1.0`), `swift`, `php`.
6. `cli`: the workflow makes a draft GitHub release; publishing the draft creates the tag `cli/v0.1.0`.
7. Install each package in an empty project with the command from the docs.

Before step 6: `go install .../licenserail-sdks/cli@latest` installs a program called `cli`, not `licenserail` (Go names it after
the last folder). Either move the program to a folder `licenserail` or point the docs to the release binaries.

## A new version

Change the version everywhere (the check lists the places; also `npm install --package-lock-only` in the three npm folders),
merge to `main`, then run the workflow per package.
