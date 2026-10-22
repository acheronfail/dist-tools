#!/usr/bin/env python3
"""Sign explicitly selected macOS code inside-out, then its containing app."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys


def sign(app_name):
    app = Path(app_name).resolve(strict=True)
    if app.suffix not in ('.app', '.plugin') or not app.is_dir():
        raise ValueError('Expected an app or plugin bundle')
    identity = os.environ.get('CODE_SIGN_IDENTITY', '')
    keychain = os.environ.get('CODE_SIGN_KEYCHAIN', '')
    if not re.fullmatch(r'[A-F0-9]{40}', identity) or not keychain:
        raise ValueError('Run through with-signing-identity.sh')

    plan_file = os.environ.get('APPLE_SIGNING_PLAN', '')
    plan = json.loads(Path(plan_file).read_text()) if plan_file else []
    if not isinstance(plan, list):
        raise ValueError('Signing plan must be a JSON array')
    targets = []
    seen = set()
    for entry in plan:
        if not isinstance(entry, dict) or set(entry) - {'path', 'entitlements'}:
            raise ValueError('Signing entries support only path and entitlements')
        relative = entry.get('path')
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            raise ValueError('Nested code paths must be relative to the app')
        target = (app / relative).resolve(strict=True)
        if target == app or app not in target.parents or target in seen:
            raise ValueError('Nested code must be unique and inside the app')
        if any(parent in seen for parent in target.parents):
            raise ValueError('Signing plan must list children before their containers')
        seen.add(target)
        targets.append((target, entry.get('entitlements', '')))
    targets.append((app, os.environ.get('APPLE_ENTITLEMENTS', '')))

    # Validate every entitlement before changing any signatures.
    for _, entitlements in targets:
        if not isinstance(entitlements, str) or (entitlements and not Path(entitlements).is_file()):
            raise ValueError('Entitlements must name an existing file')
    for target, entitlements in targets:
        command = ['codesign', '--force', '--sign', identity, '--keychain', keychain,
                   '--options', 'runtime', '--timestamp']
        if entitlements:
            command += ['--entitlements', entitlements]
        # Explicit targets preserve embedded payloads such as iOS code.
        subprocess.run(command + [str(target)], check=True, capture_output=True)


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('Usage: sign-app.py app.app')
        sign(sys.argv[1])
    except (ValueError, OSError, subprocess.CalledProcessError):
        print('App signing failed; check the signing plan, identity and entitlements.', file=sys.stderr)
        sys.exit(1)
