"""Credential health reports and issue lifecycle; no signing or submission."""

import json
import os
from pathlib import Path
import re
import subprocess

from credentials import ALLOWED, CredentialError, inspect, read_source, run


def expiry_problem(metadata):
    if not metadata['valid_now']:
        return 'expired' if metadata['days_remaining'] < 0 else 'not-yet-valid'
    days = metadata['days_remaining']
    for threshold in (30, 60, 90):
        if days <= threshold:
            return f'expires-within-{threshold}-days'
    return None


def update_issue(repo, problem_kind, problem):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}', repo) or repo.split('/')[1] in ('.', '..'):
        raise CredentialError('Invalid issue destination.')
    marker = f'<!-- dist-tools:credential-health:{problem_kind} -->'
    # Read every page rather than relying on search indexing after issue creation.
    try:
        pages = json.loads(run(['gh', 'api', '--paginate', '--slurp',
                               f'repos/{repo}/issues?state=all&per_page=100']))
        matches = sorted((issue for page in pages for issue in page
                          if not issue.get('pull_request') and marker in (issue.get('body') or '')),
                         key=lambda issue: issue['number'])
    except (ValueError, TypeError, KeyError, AttributeError):
        raise CredentialError('Unable to read existing health issues.') from None
    body = (f'{marker}\nCredential problem: **{problem}**.\n\n'
            'Update the credentials and rerun the health check.')
    if not matches:
        if problem:
            run(['gh', 'issue', 'create', '--repo', repo, '--title',
                 f'Apple credential health: {problem_kind}', '--body-file', '-'], data=body.encode())
        return
    issue = matches[0]
    if problem:
        if issue.get('body') != body:
            run(['gh', 'issue', 'edit', str(issue['number']), '--repo', repo, '--body-file', '-'], data=body.encode())
        if issue['state'] == 'closed':
            run(['gh', 'issue', 'reopen', str(issue['number']), '--repo', repo])
    elif issue['state'] == 'open':
        run(['gh', 'issue', 'close', str(issue['number']), '--repo', repo, '--reason', 'completed'])
    # Repair duplicates from an interrupted or concurrent initial creation.
    for duplicate in matches[1:]:
        if duplicate['state'] == 'open':
            run(['gh', 'issue', 'close', str(duplicate['number']), '--repo', repo, '--reason', 'not planned'])


def notary_authenticates(source):
    if (os.environ.get('GITHUB_ACTIONS'), os.environ.get('RUNNER_ENVIRONMENT'), os.environ.get('RUNNER_OS')) != ('true', 'github-hosted', 'macOS'):
        raise CredentialError('Notary health checks require a disposable GitHub-hosted macOS runner.')
    scripts = Path(__file__).resolve().parents[1] / 'scripts/apple-signing'
    env = {key: value for key, value in os.environ.items() if key not in ALLOWED}
    env.update(source)
    env['APPLE_CODE_SIGN_P12_BASE64'] = source['MACOS_CODE_SIGN_P12_BASE64']
    env['APPLE_CODE_SIGN_P12_PASSWORD'] = source['MACOS_CODE_SIGN_P12_PASSWORD']
    # Only the wrapper needs these aliases. Avoid giving the child duplicate P12s.
    env.pop('MACOS_CODE_SIGN_P12_BASE64', None)
    env.pop('MACOS_CODE_SIGN_P12_PASSWORD', None)
    for name in ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'):
        env.pop(name, None)
    try:
        result = subprocess.run(['bash', str(scripts / 'with-signing-identity.sh'),
                                 'bash', str(scripts / 'check-notary-auth.sh')], env=env,
                                capture_output=True, timeout=240)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def check(stream, *, issue_repo=None, check_notary=False):
    problems = {}
    source = None
    try:
        source = read_source(stream, signing_only=not check_notary)
        metadata = inspect(source, signing_only=not check_notary)
        problems['signing'] = expiry_problem(metadata)
    except CredentialError:
        problems['signing'] = 'invalid-credential-source'
    if check_notary and source is not None and problems['signing'] not in ('invalid-credential-source', 'expired', 'not-yet-valid'):
        problems['notary-auth'] = None if notary_authenticates(source) else 'authentication-or-import-failed'
    if issue_repo:
        for kind, problem in problems.items():
            update_issue(issue_repo, kind, problem)
    # Bucketed reports prevent public CI logs from revealing identities or dates.
    print(json.dumps({'checks': problems, 'notary_checked': 'notary-auth' in problems}, indent=2))
    # Managed issues replace repeated failed-workflow notifications.
    return 1 if any(problems.values()) and not issue_repo else 0
