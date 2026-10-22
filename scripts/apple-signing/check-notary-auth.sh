#!/usr/bin/env bash
set +x
set -euo pipefail

: "${CODE_SIGN_KEYCHAIN:?Run through with-signing-identity.sh}"
scripts="$(cd "$(dirname "$0")" && pwd)"
umask 077
work="$(mktemp -d "${RUNNER_TEMP:?}/dist-tools-auth-health.XXXXXX")"
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
profile=dist-tools-health
python3 "$scripts/notary_auth.py" "$work" "$profile"
unset APPLE_NOTARY_APPLE_ID APPLE_NOTARY_PASSWORD APPLE_NOTARY_API_KEY APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID
# A read-only request; no test app is signed or submitted.
python3 - "$profile" "$CODE_SIGN_KEYCHAIN" <<'PYTHON'
import subprocess
import sys
try:
    subprocess.run(['xcrun', 'notarytool', 'history', '--keychain-profile', sys.argv[1],
                    '--keychain', sys.argv[2], '--output-format', 'json'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=True)
except (OSError, subprocess.SubprocessError):
    raise SystemExit('Read-only notary authentication check failed.')
PYTHON
