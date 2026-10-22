"""Provider-neutral credential inspection and allowlisted GitHub synchronisation."""

import argparse
import base64
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts/apple-signing'))
from notary_auth import FIELDS, validate, AuthError

P12 = 'MACOS_CODE_SIGN_P12_BASE64'
PASSWORD = 'MACOS_CODE_SIGN_P12_PASSWORD'
ALLOWED = {P12, PASSWORD, 'APPLE_TEAM_ID', 'APPLE_NOTARY_AUTH_MODE', *FIELDS}


class CredentialError(ValueError):
    pass


def run(args, *, data=None, password=None):
    env = {key: value for key, value in os.environ.items() if key not in ALLOWED}
    env['LC_ALL'] = 'C'
    env['GH_PROMPT_DISABLED'] = '1'
    if password is not None:
        env['DIST_TOOLS_PKCS12_PASSWORD'] = password
    try:
        return subprocess.run(args, input=data, env=env, capture_output=True,
                              timeout=60, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        raise CredentialError('Credential validation or GitHub operation failed; diagnostics suppressed.') from None


def read_source(stream, *, signing_only=False):
    try:
        # Bound decrypted input; reject unknown fields rather than forwarding them.
        raw = stream.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ValueError()
        source = json.loads(raw)
        if not isinstance(source, dict) or source.keys() - ALLOWED:
            raise ValueError()
        if any(not isinstance(value, str) or '\0' in value for value in source.values()):
            raise ValueError()
        for value in source.values():
            value.encode('utf8')
        required = (P12, PASSWORD, 'APPLE_TEAM_ID') + (() if signing_only else ('APPLE_NOTARY_AUTH_MODE',))
        if not all(name in source for name in required):
            raise ValueError()
        if not re.fullmatch(r'[A-Z0-9]{10}', source['APPLE_TEAM_ID']):
            raise ValueError()
        if not signing_only:
            validate({**source, 'GITHUB_ACTIONS': 'true'})
        return source
    except (ValueError, AuthError):
        raise CredentialError('Expected one complete credential JSON object on stdin; no mixed auth modes.') from None


def inspect(source, *, signing_only=False):
    try:
        p12 = base64.b64decode(''.join(source[P12].split()), validate=True)
    except ValueError:
        raise CredentialError('Invalid PKCS12 base64.') from None
    if not p12:
        raise CredentialError('Empty PKCS12.')
    # Credential files use mode 600 inside the temporary directory.
    with tempfile.TemporaryDirectory(prefix='dist-tools-inspect-') as directory:
        directory = Path(directory)
        archive, certificate, private = [directory / name for name in ('identity.p12', 'certificate.pem', 'private.pem')]
        for file in (archive, certificate, private):
            file.touch(mode=0o600)
        archive.write_bytes(p12)
        common = ['openssl', 'pkcs12', '-in', str(archive), '-passin', 'env:DIST_TOOLS_PKCS12_PASSWORD']
        for options in (['-clcerts', '-nokeys', '-out', str(certificate)],
                        ['-nocerts', '-nodes', '-out', str(private)]):
            try:
                run(common + options, password=source[PASSWORD])
            except CredentialError:
                # macOS exports often use RC2. OpenSSL 3+ needs its legacy
                # provider to read those; the original export stays unchanged.
                run(common + ['-legacy'] + options, password=source[PASSWORD])
        if certificate.read_text().count('-----BEGIN CERTIFICATE-----') != 1:
            raise CredentialError('Expected exactly one signing certificate in the PKCS12.')
        if len(re.findall(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----', private.read_text())) != 1:
            raise CredentialError('Expected exactly one private key in the PKCS12.')
        public_key = run(['openssl', 'pkey', '-in', str(private), '-pubout'])
        certificate_key = run(['openssl', 'x509', '-in', str(certificate), '-pubkey', '-noout'])
        if public_key.split() != certificate_key.split():
            raise CredentialError('Signing certificate and private key do not match.')
        details = run(['openssl', 'x509', '-in', str(certificate), '-noout', '-subject',
                       '-nameopt', 'RFC2253', '-startdate', '-enddate', '-text']).decode()
        subject = re.search(r'^subject=\s*(.*)$', details, re.MULTILINE)
        if not subject or not re.search(r'(?:^|,)CN=Developer ID Application:', subject[1]):
            raise CredentialError('Expected a Developer ID Application certificate.')
        team = re.search(r'(?:^|,)OU=([^,]+)(?:,|$)', subject[1])
        if not team or team[1] != source['APPLE_TEAM_ID'] or '1.2.840.113635.100.6.1.13' not in details:
            raise CredentialError('Certificate type or selected team does not match.')
        try:
            start, end = [datetime.strptime(re.search(r'^' + field + r'=(.*)$', details, re.MULTILINE)[1],
                                           '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                          for field in ('notBefore', 'notAfter')]
        except (ValueError, TypeError):
            raise CredentialError('Unable to read certificate validity.') from None
        if not signing_only and source['APPLE_NOTARY_AUTH_MODE'].startswith('api-'):
            api = directory / 'api.p8'
            api.touch(mode=0o600)
            api.write_text(source['APPLE_NOTARY_API_KEY'])
            run(['openssl', 'pkey', '-in', str(api), '-check', '-noout'])
    now = datetime.now(timezone.utc)
    # Reports contain validity and auth mode, without identity fields.
    return {'certificate_kind': 'Developer ID Application', 'not_before': start.isoformat(),
            'expires_at': end.isoformat(), 'days_remaining': math.floor((end - now).total_seconds() / 86400),
            'valid_now': start <= now < end, 'auth_mode': source.get('APPLE_NOTARY_AUTH_MODE', 'not-checked')}


def select_targets(config, repositories, all_repositories):
    try:
        value = json.loads(Path(config).read_text())
        if not isinstance(value, dict) or set(value) != {'repositories'}:
            raise ValueError()
        allowlist = value['repositories']
        if not isinstance(allowlist, list) or not allowlist:
            raise ValueError()
        pattern = r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}'
        if any(not isinstance(repo, str) or not re.fullmatch(pattern, repo) or repo.split('/')[1] in ('.', '..') for repo in allowlist):
            raise ValueError()
        lookup = {repo.lower(): repo for repo in allowlist}
        if len(lookup) != len(allowlist):
            raise ValueError()
        selected = allowlist if all_repositories else repositories
        if not selected or any(repo.lower() not in lookup for repo in selected):
            raise ValueError()
        return list(dict.fromkeys(lookup[repo.lower()] for repo in selected))
    except (OSError, ValueError, KeyError, TypeError):
        raise CredentialError('Invalid allowlist or target repository is not allowlisted.') from None


def payload(source):
    mode = source['APPLE_NOTARY_AUTH_MODE']
    names = FIELDS[:2] if mode == 'apple-id' else FIELDS[2:]
    secrets = {name: source[name] for name in (P12, PASSWORD, *names) if name in source and source[name]}
    # PKCS12 passwords may legitimately be empty.
    secrets[PASSWORD] = source[PASSWORD]
    # The secret masks team IDs in logs; the variable supports existing consumers.
    secrets['APPLE_TEAM_ID'] = source['APPLE_TEAM_ID']
    if any(len(value.encode()) > 48 * 1024 for value in secrets.values()):
        raise CredentialError('A credential exceeds the GitHub Actions secret size limit.')
    return secrets, {name: source[name] for name in ('APPLE_TEAM_ID', 'APPLE_NOTARY_AUTH_MODE')}


def main(argv=None):
    # Raise through TemporaryDirectory so termination removes decrypted material.
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description='Inspect, sync or check credential JSON from stdin.')
    parser.add_argument('apple', choices=['apple'])
    parser.add_argument('credentials', choices=['credentials'])
    parser.add_argument('operation', choices=['inspect', 'sync', 'health'])
    parser.add_argument('--config', help='JSON repository allowlist (required for sync)')
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--repo', action='append', help='Explicit allowlisted target; repeatable')
    selection.add_argument('--all', action='store_true', help='All repositories in the allowlist')
    parser.add_argument('--dry-run', action='store_true', help='Validate and show targets without any GitHub calls')
    parser.add_argument('--issue-repo', help='Publish deduplicated health issues to this explicit repository')
    parser.add_argument('--check-notary', action='store_true', help='Also validate auth/import on a disposable hosted Mac')
    args = parser.parse_args(argv)
    try:
        if args.operation == 'health':
            if args.config or args.repo or args.all or args.dry_run:
                raise CredentialError('Sync options do not apply to health checks.')
            from health import check
            return check(sys.stdin, issue_repo=args.issue_repo, check_notary=args.check_notary)
        if args.issue_repo or args.check_notary:
            raise CredentialError('Health options apply only to health checks.')
        targets = []
        if args.operation == 'sync':
            targets = select_targets(args.config, args.repo, args.all)
        elif args.config or args.repo or args.all or args.dry_run:
            raise CredentialError('Repository selection and dry-run options apply only to sync.')
        source = read_source(sys.stdin)
        metadata = inspect(source)
        secrets, variables = payload(source)
        report = {'inspection': metadata}
        if args.operation == 'inspect':
            print(json.dumps(report, indent=2))
            return 0 if metadata['valid_now'] else 1
        if not metadata['valid_now']:
            raise CredentialError('Signing certificate is expired or not yet valid; no writes performed.')
        report.update({'dry_run': args.dry_run, 'targets': targets,
                       'secret_names': list(secrets), 'variable_names': list(variables)})
        if args.dry_run:
            print(json.dumps(report, indent=2))
            return 0
        results = []
        for repo in targets:
            completed = []
            try:
                for kind, values in (('secret', secrets), ('variable', variables)):
                    for name, value in values.items():
                        run(['gh', kind, 'set', name, '--repo', repo], data=value.encode())
                        completed.append(name)
                results.append({'repository': repo, 'status': 'updated'})
            except CredentialError:
                results.append({'repository': repo, 'status': 'failed', 'completed': completed,
                                'message': 'Partial updates are possible. Correct the failure and rerun the same source.'})
        report['results'] = results
        print(json.dumps(report, indent=2))
        return 1 if any(result['status'] == 'failed' for result in results) else 0
    except CredentialError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        print('Credential operation failed; private diagnostics were suppressed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
