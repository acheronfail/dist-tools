# dist-tools

Sign, notarize, staple and package a macOS app or plugin for direct download.
Includes a stdin CLI for credential sync and an opt-in credential-health workflow.
Builds and release publication stay in the caller's repository.

## GitHub Action

Use a disposable **GitHub-hosted macOS runner** with Xcode command-line tools and
Python 3 and a Developer ID Application certificate:

```yaml
- uses: OWNER/dist-tools/actions/apple-release@v1
  with:
    app-path: build/MyApp.app
    bundle-id: com.example.myapp
    output-archive: build/MyApp.zip
    team-id: ${{ secrets.APPLE_TEAM_ID }}
    p12-base64: ${{ secrets.MACOS_CODE_SIGN_P12_BASE64 }}
    p12-password: ${{ secrets.MACOS_CODE_SIGN_P12_PASSWORD }}
    notary-auth-mode: api-team
    notary-api-key: ${{ secrets.APPLE_NOTARY_API_KEY }}
    notary-key-id: ${{ secrets.APPLE_NOTARY_KEY_ID }}
    notary-issuer-id: ${{ secrets.APPLE_NOTARY_ISSUER_ID }}
```

The output directory must exist. The Action modifies the app in place, uses a
temporary signing keychain, and verifies its signature, stapled ticket and
notarization before replacing the output ZIP. Apps also pass Gatekeeper execution
assessment. Rebuild from clean input after failure. Failed submissions are not
automatically resubmitted.

`v1` tracks compatible updates; `v1.0.0` selects the initial release. A full
commit SHA pins the exact code. See [action.yml](actions/apple-release/action.yml)
for all inputs and defaults.

`app-path` also accepts `.plugin` bundles. Plugins use a notarization requirement
check (`codesign --check-notarization`) instead of app execution assessment.
Nested plugin libraries belong in the signing plan below.

### Authentication

Supply only the inputs for the selected `notary-auth-mode`:

| Mode | Inputs | Xcode |
| --- | --- | --- |
| `api-team` | `notary-api-key` (PEM text), `notary-key-id`, `notary-issuer-id` | 14+ |
| `api-individual` | `notary-api-key`, `notary-key-id`; omit issuer | 26+ |
| `apple-id` (default) | `notary-apple-id`, `notary-password` (app-specific password) | 14+ |

A team API key with the Developer role supports notarization. API keys do not
replace the signing certificate. See [credential setup and sync](docs/credentials.md).

### Nested code and audits

By default, only the outer app is signed with hardened runtime and a timestamp.
For nested macOS code, pass `signing-plan`: a JSON file listing app-relative paths
in signing order, children before containers. Entitlement files are relative to
the working directory:

```json
[
  {"path": "Contents/Frameworks/Helper.framework/Versions/A/Helper"},
  {"path": "Contents/Frameworks/Helper.framework"},
  {"path": "Contents/PlugIns/Extension.appex", "entitlements": "release/extension.plist"}
]
```

Use `entitlements` for the outer app. List every nested macOS code target requiring
signing; leave embedded payloads that must retain their original bytes unlisted.
Signing is non-recursive. Architecture and app-specific preflight checks run
in the caller.

`post-sign-command` runs trusted Bash before notarization with `APPLE_RELEASE_APP`
set and notarization credentials removed from its environment:

```yaml
post-sign-command: '"$APPLE_RELEASE_APP/Contents/MacOS/myapp" --check-runtime'
```

`notary-timeout` defaults to `20m` (range `1m`–`60m`). Allow additional job time for
signing and ticket retries. `ticket-network-workaround: 'true'` optionally blocks
UDP 443 for the rest of the hosted job to work around
[runner ticket lookup failures](https://github.com/actions/runner-images/issues/14924).

## Development

```sh
node --test tests/*.test.mjs
for script in scripts/apple-signing/*.sh; do bash -n "$script" || exit; done
```

Tests use mocked Apple tools and generated certificates.
