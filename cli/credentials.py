"""Apple signing credentials and repository sync."""

import argparse
import base64
from datetime import datetime, timezone
import getpass
import io
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
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / 'repositories.yaml'
DEFAULT_CREDENTIALS = ROOT / '.local/credentials.json'


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
        message = ('GitHub update failed. Check gh authentication and repository access.' if args[0] == 'gh' else
                   'Credential validation failed. Check the certificate, export password and API key.')
        raise CredentialError(message) from None


def read_source(stream):
    try:
        # Bound decrypted input; reject unknown fields rather than forwarding them.
        raw = stream.read(1_048_577)
        if not raw.strip():
            raise CredentialError('No credential JSON received. Run interactively to choose a file, '
                                  'or redirect input with < .local/credentials.json.')
        if len(raw) > 1_048_576:
            raise ValueError()
        source = json.loads(raw)
        if not isinstance(source, dict) or source.keys() - ALLOWED:
            raise ValueError()
        if any(not isinstance(value, str) or '\0' in value for value in source.values()):
            raise ValueError()
        for value in source.values():
            value.encode('utf8')
        required = (P12, PASSWORD, 'APPLE_TEAM_ID')
        if not all(name in source for name in required):
            raise ValueError()
        if not re.fullmatch(r'[A-Z0-9]{10}', source['APPLE_TEAM_ID']):
            raise ValueError()
        if 'APPLE_NOTARY_AUTH_MODE' not in source:
            source['APPLE_NOTARY_AUTH_MODE'] = (
                'apple-id' if any(source.get(name) for name in FIELDS[:2]) else
                'api-team' if source.get('APPLE_NOTARY_ISSUER_ID') else 'api-individual')
        validate({**source, 'GITHUB_ACTIONS': 'true'})
        return source
    except CredentialError:
        raise
    except (ValueError, AuthError):
        raise CredentialError('Expected a complete credential JSON object with one notarization auth mode.') from None


def inspect(source):
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
        if source['APPLE_NOTARY_AUTH_MODE'].startswith('api-'):
            api = directory / 'api.p8'
            api.touch(mode=0o600)
            api.write_text(source['APPLE_NOTARY_API_KEY'])
            run(['openssl', 'pkey', '-in', str(api), '-check', '-noout'])
    now = datetime.now(timezone.utc)
    # Reports contain validity and auth mode, without identity fields.
    return {'certificate_kind': 'Developer ID Application', 'not_before': start.isoformat(),
            'expires_at': end.isoformat(), 'days_remaining': math.floor((end - now).total_seconds() / 86400),
            'valid_now': start <= now < end, 'auth_mode': source['APPLE_NOTARY_AUTH_MODE']}


def load_repositories(config):
    try:
        pattern = r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}'
        # Read the repositories field as a YAML block list of repository strings.
        entry = re.compile(r'^( *)- +([\'"]?)(' + pattern + r')\2(?: +#.*)? *$')
        repositories, indentation, header = [], None, False
        for line in Path(config).read_text(encoding='utf-8-sig').splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            if not header:
                if not re.fullmatch(r'repositories: *(?:#.*)?', line):
                    raise ValueError()
                header = True
                continue
            match = entry.fullmatch(line)
            if not match or (indentation is not None and match[1] != indentation):
                raise ValueError()
            indentation = match[1]
            repo = match[3]
            if repo.split('/')[1] in ('.', '..'):
                raise ValueError()
            repositories.append(repo)
        if not repositories or len({repo.lower() for repo in repositories}) != len(repositories):
            raise ValueError()
        return repositories
    except FileNotFoundError:
        raise CredentialError('Copy repositories.example.yaml to repositories.yaml in the dist-tools checkout '
                              'and edit the repository list.') from None
    except (OSError, ValueError, TypeError):
        raise CredentialError('Invalid repository config; use a repositories: list of unique owner/repo names.') from None


def save_credentials(credentials, source, *, replace=False):
    credentials = Path(credentials)
    metadata = inspect(read_source(io.StringIO(json.dumps(source))))
    if not metadata['valid_now']:
        raise CredentialError('Certificate is expired or not yet valid; credentials unchanged.')
    credentials.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.credentials-', dir=credentials.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(source, stream, indent=2)
            stream.write('\n')
        if replace:
            os.replace(temporary, credentials)
        else:
            os.link(temporary, credentials)
    finally:
        Path(temporary).unlink(missing_ok=True)


def create(credentials, p12, api_key, team, key_id, issuer, password):
    if Path(credentials).exists():
        raise CredentialError('Credential JSON already exists; use renew to replace its certificate.')
    source = {P12: base64.b64encode(Path(p12).read_bytes()).decode(), PASSWORD: password,
              'APPLE_TEAM_ID': team, 'APPLE_NOTARY_API_KEY': Path(api_key).read_text(),
              'APPLE_NOTARY_KEY_ID': key_id}
    if issuer:
        source['APPLE_NOTARY_ISSUER_ID'] = issuer
    save_credentials(credentials, source)


def renew(credentials, p12, password):
    with Path(credentials).open() as stream:
        source = json.load(stream)
    if not isinstance(source, dict):
        raise CredentialError('Expected a credential JSON object.')
    source[P12] = base64.b64encode(Path(p12).read_bytes()).decode()
    source[PASSWORD] = password
    save_credentials(credentials, source, replace=True)


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
    parser = argparse.ArgumentParser(description='Manage Apple signing credentials.')
    apple = parser.add_subparsers(required=True).add_parser('apple')
    credentials = apple.add_subparsers(required=True).add_parser('credentials')
    operations = credentials.add_subparsers(dest='operation', required=True)
    operations.add_parser('inspect', help='Inspect credentials without contacting GitHub')
    sync = operations.add_parser('sync', help='Sync credentials to every configured repository')
    sync.add_argument('--config', default=DEFAULT_CONFIG,
                      help='YAML repository list (default: repositories.yaml in the dist-tools checkout)')
    sync.add_argument('--dry-run', action='store_true', help='Validate and show targets without any GitHub calls')
    for operation, description in (('create', 'Create credential JSON from .p12 and .p8 files'),
                                   ('renew', 'Replace only the certificate in your credential JSON')):
        command = operations.add_parser(operation, help=description)
        command.add_argument('--credentials', type=Path, default=DEFAULT_CREDENTIALS,
                             help='Credential JSON (default: .local/credentials.json in the dist-tools checkout)')
    args = parser.parse_args(argv)
    try:
        if args.operation in ('create', 'renew'):
            if args.operation == 'create' and args.credentials.exists():
                raise CredentialError('Credential JSON already exists; use renew to replace its certificate.')
            if args.operation == 'renew' and not args.credentials.is_file():
                raise CredentialError('Credential JSON file not found. Export it from your password manager before renewing.')
            if not sys.stdin.isatty():
                raise CredentialError('Run this command in a terminal to enter the PKCS12 password.')
            p12 = Path(input('Developer ID Application .p12 path: ').strip()).expanduser()
            if not p12.is_file():
                raise CredentialError('The .p12 path must name an existing file.')
            if args.operation == 'create':
                api_key = Path(input('App Store Connect API .p8 path: ').strip()).expanduser()
                if not api_key.is_file():
                    raise CredentialError('The .p8 path must name an existing file.')
            password = getpass.getpass('PKCS12 export password: ')
            if args.operation == 'create':
                create(args.credentials, p12, api_key, input('Apple Team ID: ').strip(),
                       input('API Key ID: ').strip(), input('Issuer ID (blank for an individual key): ').strip(), password)
            else:
                renew(args.credentials, p12, password)
            print('Credentials saved. Update your password-manager copy, then run sync.')
            return 0
        targets = load_repositories(args.config) if args.operation == 'sync' else []
        if sys.stdin.isatty():
            filename = input('Credential JSON path [.local/credentials.json]: ').strip()
            path = Path(filename).expanduser() if filename else DEFAULT_CREDENTIALS
            if not path.is_file():
                raise CredentialError('Credential JSON file not found. Export it from your password manager first.')
            with path.open() as stream:
                source = read_source(stream)
        else:
            source = read_source(sys.stdin)
        metadata = inspect(source)
        report = {'inspection': metadata}
        if args.operation == 'inspect':
            print(json.dumps(report, indent=2))
            return 0 if metadata['valid_now'] else 1
        if not metadata['valid_now']:
            raise CredentialError('Signing certificate is expired or not yet valid; no writes performed.')
        secrets, variables = payload(source)
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
            except CredentialError as error:
                results.append({'repository': repo, 'status': 'failed', 'completed': completed,
                                'message': f'{error} Partial updates are possible; correct the failure and rerun.'})
        report['results'] = results
        print(json.dumps(report, indent=2))
        return 1 if any(result['status'] == 'failed' for result in results) else 0
    except EOFError:
        print('Input cancelled.', file=sys.stderr)
        return 1
    except CredentialError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        print('Unable to read or update credentials. Check the input files and their permissions.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
