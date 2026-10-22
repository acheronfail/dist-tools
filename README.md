# dist-tools

Sign and notarize macOS apps and plugins, package ZIPs and DMGs, and sync Apple
credentials across GitHub repositories. Caller repositories build apps and publish releases.

## GitHub Action

Run after building your app, on a GitHub-hosted macOS runner:

```yaml
- uses: OWNER/dist-tools/actions/apple-release@v1
  with:
    app-path: build/MyApp.app
    bundle-id: com.example.myapp
    output-archive: build/MyApp.zip
    output-disk-image: build/MyApp.dmg # optional; apps only
    team-id: ${{ secrets.APPLE_TEAM_ID }}
    p12-base64: ${{ secrets.MACOS_CODE_SIGN_P12_BASE64 }}
    p12-password: ${{ secrets.MACOS_CODE_SIGN_P12_PASSWORD }}
    notary-auth-mode: ${{ vars.APPLE_NOTARY_AUTH_MODE }}
    notary-api-key: ${{ secrets.APPLE_NOTARY_API_KEY }}
    notary-key-id: ${{ secrets.APPLE_NOTARY_KEY_ID }}
    notary-issuer-id: ${{ secrets.APPLE_NOTARY_ISSUER_ID }}
```

The output directory must exist. The Action signs the bundle in place, notarizes,
staples and verifies it, then creates the packages. `app-path` also accepts
`.plugin` bundles. `v1` tracks compatible updates; use a full SHA to pin a version.
See [action.yml](actions/apple-release/action.yml) for optional inputs.

For nested code, pass `signing-plan`, a JSON list of bundle-relative paths in
signing order, children first:

```json
[
  {"path": "Contents/Frameworks/Helper.framework/Versions/A/Helper"},
  {"path": "Contents/Frameworks/Helper.framework"}
]
```

Entries may include `"entitlements": "path/to/file.plist"` or
`"preserve-entitlements": true`. Use the Action's `entitlements` input for the
outer app. Only the listed nested targets and the outer bundle are signed.

The example uses an App Store Connect team API key. Individual keys omit
`notary-issuer-id` and require Xcode 26+. Apple Account authentication instead uses
`notary-auth-mode: apple-id`, `notary-apple-id` and `notary-password`.

## Setup and renewal

The CLI needs Python 3 and OpenSSL. Sync also needs authenticated `gh` with
access to manage Actions secrets and variables in each target repository.

Already set up? Restore `repositories.yaml`, export your saved credential JSON
to `.local/credentials.json`, then run `bin/dist-tools apple credentials sync`.

**First time**

1. Copy `repositories.example.yaml` to `repositories.yaml` and edit its `repositories:` list.
   This local file is ignored by Git. Keep a copy with your credential backup.
2. Create a [Developer ID Application certificate](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/)
   using a [Keychain Access certificate signing request](https://developer.apple.com/help/account/certificates/create-a-certificate-signing-request).
   Choose G2 if prompted. Install the downloaded certificate on the same Mac,
   then [export it with its private key as a password-protected `.p12`](https://help.apple.com/xcode/mac/current/en.lproj/dev154b28f09.html).
3. Create an [App Store Connect team API key](https://developer.apple.com/documentation/appstoreconnectapi/creating-api-keys-for-app-store-connect-api)
   with the Developer role. Download its `.p8` file and note the Key ID, Issuer ID
   and your Apple Team ID.
4. Create the credential JSON; the command prompts for both file paths, the IDs
   and the `.p12` password:

   ```sh
   bin/dist-tools apple credentials create
   ```

   Save the resulting `.local/credentials.json` in your password manager.
5. Sync every repository in `repositories.yaml`:

   ```sh
   bin/dist-tools apple credentials sync
   ```

**When the certificate expires**

Create and export a replacement Developer ID Application certificate as above.
Export your saved JSON from your password manager to `.local/credentials.json`, then:

```sh
bin/dist-tools apple credentials renew
bin/dist-tools apple credentials sync
```

`renew` prompts for the new `.p12` path and export password, then replaces only
`MACOS_CODE_SIGN_P12_BASE64` and `MACOS_CODE_SIGN_P12_PASSWORD`. Save the updated
JSON back to your password manager. Team and Issuer IDs stay the same; API keys
need replacing only when rotated or revoked. Follow the certificate's expiry date;
[Apple's current G2 guidance is annual renewal](https://developer.apple.com/news/?id=w4atic4c).

Check every repo reports `updated`, then remove the temporary JSON export.
`sync` and `inspect` prompt for the JSON path, defaulting to `.local/credentials.json`
in this checkout. Both also accept piped or redirected JSON.
Sync validates credentials locally; the next signed build checks Apple acceptance.
Use `sync --dry-run` to preview without GitHub calls, or `inspect` to check expiry.
