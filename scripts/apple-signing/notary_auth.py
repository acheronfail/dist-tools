#!/usr/bin/env python3
"""Validate one notarisation auth mode and register it without public diagnostics."""

import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import uuid

FIELDS = ('APPLE_NOTARY_APPLE_ID', 'APPLE_NOTARY_PASSWORD', 'APPLE_NOTARY_API_KEY',
          'APPLE_NOTARY_KEY_ID', 'APPLE_NOTARY_ISSUER_ID')


class AuthError(ValueError):
    pass


def validate(env):
    mode = env.get('APPLE_NOTARY_AUTH_MODE') or (
        'apple-id' if env.get('GITHUB_ACTIONS') == 'true' else 'keychain')
    account = any(env.get(name) for name in FIELDS[:2])
    api = any(env.get(name) for name in FIELDS[2:])
    if mode == 'keychain':
        if account or api or env.get('GITHUB_ACTIONS') == 'true':
            raise AuthError('Keychain mode is local-only and rejects supplied credentials.')
    elif mode == 'apple-id':
        if api or not all(env.get(name) for name in FIELDS[:2]):
            raise AuthError('Apple Account mode requires email/password and rejects API credentials.')
    elif mode in ('api-team', 'api-individual'):
        if account or not env.get('APPLE_NOTARY_API_KEY') or not re.fullmatch(
                r'[A-Z0-9]{10,}', env.get('APPLE_NOTARY_KEY_ID', '')):
            raise AuthError('API mode requires a private key and valid key ID, without Apple Account credentials.')
        issuer = env.get('APPLE_NOTARY_ISSUER_ID', '')
        if mode == 'api-team':
            try:
                if str(uuid.UUID(issuer)) != issuer.lower():
                    raise ValueError()
            except (ValueError, AttributeError):
                raise AuthError('Team API keys require a UUID issuer ID.') from None
        elif issuer:
            raise AuthError('Individual API keys must not include an issuer ID.')
    else:
        raise AuthError('Unsupported notarisation auth mode.')
    return mode


def clean_environment():
    return {key: value for key, value in os.environ.items() if key not in FIELDS}


def quiet_run(args, env):
    try:
        return subprocess.run(args, env=env, capture_output=True, timeout=120, check=True)
    except (OSError, subprocess.SubprocessError):
        # Tool output can contain key material, account names or server details.
        raise AuthError('Notary credential validation failed; tool diagnostics were suppressed.') from None


def store(work, profile):
    mode = validate(os.environ)
    if mode == 'keychain':
        return
    keychain = os.environ.get('CODE_SIGN_KEYCHAIN')
    if not keychain:
        raise AuthError('Credential registration requires the disposable signing keychain.')
    env = clean_environment()
    arguments = ['xcrun', 'notarytool', 'store-credentials', profile,
                 '--keychain', keychain, '--validate']
    key_path = None
    try:
        if mode == 'apple-id':
            arguments += ['--apple-id', os.environ['APPLE_NOTARY_APPLE_ID'],
                          '--password', os.environ['APPLE_NOTARY_PASSWORD'],
                          '--team-id', os.environ['APPLE_TEAM_ID']]
        else:
            version = quiet_run(['xcodebuild', '-version'], env).stdout.decode(errors='replace')
            match = re.search(r'^Xcode (\d+)', version, re.MULTILINE)
            minimum = 26 if mode == 'api-individual' else 14
            if not match or int(match[1]) < minimum:
                raise AuthError(f'This API auth mode requires Xcode {minimum} or later.')
            key_path = Path(work) / 'notary-key.p8'
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(os.environ['APPLE_NOTARY_API_KEY'])
            quiet_run(['openssl', 'pkey', '-in', str(key_path), '-check', '-noout'], env)
            arguments += ['--key', str(key_path), '--key-id', os.environ['APPLE_NOTARY_KEY_ID']]
            if mode == 'api-team':
                arguments += ['--issuer', os.environ['APPLE_NOTARY_ISSUER_ID']]
        quiet_run(arguments, env)
    finally:
        if key_path is not None:
            key_path.unlink(missing_ok=True)


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if sys.argv[1:] == ['--validate']:
            validate(os.environ)
        elif len(sys.argv) == 3:
            store(sys.argv[1], sys.argv[2])
        else:
            raise AuthError('Usage: notary_auth.py --validate | work-directory profile')
    except (AuthError, OSError, KeyError):
        # Exception details can contain input values and credential paths.
        print('Notary authentication configuration or validation failed.', file=sys.stderr)
        sys.exit(1)
