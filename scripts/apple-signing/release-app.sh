#!/usr/bin/env bash
set +x
set -euo pipefail

app="${1:?Usage: release-app.sh app.app output.zip bundle.id}"
output="${2:?Usage: release-app.sh app.app output.zip bundle.id}"
bundle_id="${3:?Set the expected bundle ID}"
scripts="$(cd "$(dirname "$0")" && pwd)"

# Validate inputs before changing signatures or runner networking.
[[ "$APPLE_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo 'Invalid Apple Team ID.' >&2; exit 2; }
[[ "$bundle_id" =~ ^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$ ]] || { echo 'Invalid bundle ID.' >&2; exit 2; }
[[ -d "$app" && ( "$app" == *.app || "$app" == *.plugin ) && "$output" == *.zip ]] || { echo 'Expected an app or plugin bundle and ZIP output.' >&2; exit 2; }
if [[ -n "${APPLE_RELEASE_DMG:-}" ]]; then
    [[ "$app" == *.app && "$APPLE_RELEASE_DMG" == *.dmg && -d "$(dirname "$APPLE_RELEASE_DMG")" && ! -d "$APPLE_RELEASE_DMG" ]] || { echo 'Disk image output requires an app and a DMG path in an existing directory.' >&2; exit 2; }
fi
timeout="${APPLE_NOTARY_TIMEOUT:-20m}"
[[ "$timeout" =~ ^([1-9]|[1-5][0-9]|60)m$ ]] || { echo 'Notary timeout must be between 1m and 60m.' >&2; exit 2; }
python3 "$scripts/notary_auth.py" --validate
case "${APPLE_TICKET_NETWORK_WORKAROUND:-false}" in
    true) bash "$scripts/ticket-network-workaround.sh" ;;
    false) ;;
    *) echo 'Ticket network workaround must be true or false.' >&2; exit 2 ;;
esac

# The identity wrapper removes certificate secrets; this also removes notary
# credentials from codesign and consumer audit environments.
(
    unset APPLE_NOTARY_APPLE_ID APPLE_NOTARY_PASSWORD APPLE_NOTARY_API_KEY APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID
    python3 "$scripts/sign-app.py" "$app"
    if [[ -n "${APPLE_POST_SIGN_COMMAND:-}" ]]; then
        export APPLE_RELEASE_APP="$app"
        bash -euo pipefail -c "$APPLE_POST_SIGN_COMMAND"
    fi
)
bash "$scripts/notarize-app.sh" "$app" "$output" "$bundle_id"

if [[ -n "${APPLE_RELEASE_DMG:-}" ]]; then
    umask 077
    disk_work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/dist-tools-dmg.XXXXXX")"
    trap 'rm -rf "$disk_work"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    (
        unset APPLE_NOTARY_APPLE_ID APPLE_NOTARY_PASSWORD APPLE_NOTARY_API_KEY APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID
        name="$(basename "${app%.app}")"
        mkdir -m 755 "$disk_work/staging"
        ditto "$app" "$disk_work/staging/$name.app"
        ln -s /Applications "$disk_work/staging/Applications"
        hdiutil create -volname "$name" -srcfolder "$disk_work/staging" -ov -format UDZO "$disk_work/signed.dmg"
        if ! codesign --force --sign "$CODE_SIGN_IDENTITY" --keychain "$CODE_SIGN_KEYCHAIN" \
            --timestamp --identifier "$bundle_id" "$disk_work/signed.dmg" >/dev/null 2>&1; then
            echo 'Disk image signing failed; check the signing identity and keychain.' >&2
            exit 1
        fi
    )
    bash "$scripts/notarize-app.sh" "$disk_work/signed.dmg" "$APPLE_RELEASE_DMG" "$bundle_id"
fi
