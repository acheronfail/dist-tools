#!/usr/bin/env bash
set +x
set -euo pipefail

app="${1:?Usage: notarize-app.sh app.app output.zip bundle.id}"
output="${2:?Usage: notarize-app.sh app.app output.zip bundle.id}"
bundle_id="${3:?Set the expected bundle ID as the third argument}"
timeout="${APPLE_NOTARY_TIMEOUT:-20m}"
[[ "$bundle_id" =~ ^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$ ]] || { echo 'Invalid bundle ID.' >&2; exit 2; }
[[ "$timeout" =~ ^([1-9]|[1-5][0-9]|60)m$ ]] || { echo 'Notary timeout must be between 1m and 60m.' >&2; exit 2; }
: "${APPLE_TEAM_ID:?Set the publishing Apple Team ID}"
[[ "$APPLE_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo 'Invalid Apple Team ID.' >&2; exit 2; }
disk_image=false
if [[ -f "$app" && "$app" == *.dmg && "$output" == *.dmg ]]; then
    disk_image=true
elif [[ ! -d "$app" || ( "$app" != *.app && "$app" != *.plugin ) || "$output" != *.zip ]]; then
    echo 'Expected an app/plugin with ZIP output, or a disk image with DMG output.' >&2
    exit 2
fi
verification=(--verify --strict)
if [[ "$disk_image" == false ]]; then verification+=(--deep); fi
requirement="anchor apple generic and identifier \"$bundle_id\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$APPLE_TEAM_ID\""
scripts="$(cd "$(dirname "$0")" && pwd)"
python3 "$scripts/notary_auth.py" --validate
(
    unset APPLE_NOTARY_APPLE_ID APPLE_NOTARY_PASSWORD APPLE_NOTARY_API_KEY APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID
    codesign "${verification[@]}" --test-requirement "=$requirement" "$app"
)
umask 077
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/dist-tools-notary.XXXXXX")"
archive=""
cleanup() {
    rm -rf "$work"
    if [[ -n "$archive" ]]; then rm -f "$archive"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

profile="${APPLE_NOTARY_KEYCHAIN_PROFILE:-dist-tools-notary}"
authentication=(--keychain-profile "$profile")
auth_mode="${APPLE_NOTARY_AUTH_MODE:-keychain}"
if [[ -z "${APPLE_NOTARY_AUTH_MODE:-}" && "${GITHUB_ACTIONS:-}" == true ]]; then auth_mode=apple-id; fi
if [[ "$auth_mode" != keychain ]]; then
    python3 "$scripts/notary_auth.py" "$work" "$profile"
    authentication+=(--keychain "$CODE_SIGN_KEYCHAIN")
fi

unset APPLE_NOTARY_APPLE_ID APPLE_NOTARY_PASSWORD APPLE_NOTARY_API_KEY APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID
if [[ "$disk_image" == true ]]; then
    ditto "$app" "$work/upload.dmg"
    app="$work/upload.dmg"
    submission="$app"
else
    submission="$work/upload.zip"
    ditto -c -k --sequesterRsrc --keepParent "$app" "$submission"
fi
submit_status=0
xcrun notarytool submit "$submission" "${authentication[@]}" \
    --wait --timeout "$timeout" --output-format json > "$work/result.json" || submit_status=$?
# A transport error, timeout, malformed response or rejection never publishes a
# replacement archive. Preserve the submission ID so a timed-out job is traceable.
result="$(python3 - "$work/result.json" <<'PYTHON'
import json
import sys
import uuid
with open(sys.argv[1]) as stream:
    result = json.load(stream)
identifier, status = result.get('id', ''), result.get('status', '')
try:
    identifier = str(uuid.UUID(identifier))
except (ValueError, AttributeError, TypeError):
    raise SystemExit('Invalid notarization submission ID; no archive was published')
if status not in ('Accepted', 'Invalid', 'In Progress', 'Rejected'):
    raise SystemExit('Unexpected notarization response; no archive was published')
print(identifier, status)
PYTHON
)"
submission_id="${result%% *}"
status="${result#* }"
printf 'Notarization submission %s: %s\n' "$submission_id" "$status"
if [[ "$submit_status" != 0 || "$status" != Accepted ]]; then
    # Only completed rejections have a useful log. Keep it out of public release
    # assets; Xcode may include package paths and other implementation details.
    if [[ "$status" == Invalid || "$status" == Rejected ]]; then
        xcrun notarytool log "$submission_id" "${authentication[@]}" "$work/log.json" || true
        if [[ -f "$work/log.json" ]]; then
            python3 - "$work/log.json" <<'PYTHON'
import json
import sys
with open(sys.argv[1]) as stream:
    result = json.load(stream)
for issue in result.get('issues') or []:
    print('Notarization issue:', issue.get('code'), issue.get('message'))
PYTHON
        fi
    fi
    echo 'Notarization did not complete successfully; no archive was published.' >&2
    exit 1
fi
# Ticket delivery can fail transiently after Apple accepts the submission.
# Retry CloudKit lookup failures (68), without resubmitting or bypassing checks.
for action in staple validate; do
    for attempt in 1 2 3 4; do
        staple_status=0
        xcrun stapler "$action" "$app" || staple_status=$?
        if [[ "$staple_status" == 0 ]]; then break; fi
        if [[ "$staple_status" != 68 || "$attempt" == 4 ]]; then
            printf 'Stapler %s failed; no archive was published.\n' "$action" >&2
            exit "$staple_status"
        fi
        delay=$((attempt * 5))
        printf 'Ticket lookup failed; retrying stapler %s in %s seconds (attempt %s/4).\n' "$action" "$delay" "$((attempt + 1))" >&2
        sleep "$delay"
    done
done
codesign "${verification[@]}" --test-requirement "=$requirement" "$app"
if [[ "$app" == *.plugin ]]; then
    codesign --verify --deep --strict --check-notarization --test-requirement "=$requirement and notarized" "$app"
elif [[ "$disk_image" == true ]]; then
    spctl --assess --type open --context context:primary-signature "$app"
else
    spctl --assess --type execute "$app"
fi

# Bundle ZIPs are rebuilt after stapling. Disk images retain their own ticket.
archive="$(mktemp "$(dirname "$output")/.dist-tools-notarized.XXXXXX")"
if [[ "$disk_image" == true ]]; then
    ditto "$app" "$archive"
    hdiutil verify "$archive"
else
    ditto -c -k --sequesterRsrc --keepParent "$app" "$archive"
    unzip -tq "$archive"
fi
mv -f "$archive" "$output"
archive=""
printf 'Notarized macOS output: %s\n' "$output"
