import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { after, test } from 'node:test';

const root = new URL('../', import.meta.url).pathname;
const work = mkdtempSync(join(tmpdir(), 'dist-tools-cli-test-'));
after(() => rmSync(work, { recursive: true, force: true }));
function openssl(args) {
  const result = spawnSync('openssl', args, { encoding: 'utf8' });
  assert.equal(result.status, 0, 'Synthetic credential fixture generation failed');
  return result.stdout;
}
const key = join(work, 'key.pem'), cert = join(work, 'certificate.pem');
const configuration = join(work, 'openssl.cnf');
writeFileSync(configuration, `[req]
distinguished_name=dn
x509_extensions=extensions
prompt=no
[dn]
CN=Developer ID Application: Example Fixture
OU=TESTTEAM01
[extensions]
1.2.840.113635.100.6.1.13=DER:05:00
`);
openssl(['req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '365',
  '-config', configuration, '-keyout', key, '-out', cert]);
function archive(certificate, options = []) {
  const file = join(work, 'identity.p12');
  openssl(['pkcs12', '-export', '-inkey', key, '-in', certificate, '-out', file, '-passout', 'pass:synthetic-password', ...options]);
  return readFileSync(file).toString('base64');
}
const source = {
  MACOS_CODE_SIGN_P12_BASE64: archive(cert), MACOS_CODE_SIGN_P12_PASSWORD: 'synthetic-password',
  APPLE_TEAM_ID: 'TESTTEAM01', APPLE_NOTARY_AUTH_MODE: 'apple-id',
  APPLE_NOTARY_APPLE_ID: 'test@example.invalid', APPLE_NOTARY_PASSWORD: 'notary-secret-sentinel',
};
const expiredCert = join(work, 'expired.pem');
const request = join(work, 'request.pem');
openssl(['req', '-new', '-key', key, '-config', configuration, '-out', request]);
writeFileSync(join(work, 'index'), '');
writeFileSync(join(work, 'serial'), '01\n');
const caConfig = join(work, 'ca.cnf');
writeFileSync(caConfig, `[ca]
default_ca=local
[local]
database=${join(work, 'index')}
serial=${join(work, 'serial')}
new_certs_dir=${work}
default_md=sha256
policy=policy
[policy]
commonName=supplied
organizationalUnitName=supplied
[extensions]
1.2.840.113635.100.6.1.13=DER:05:00
`);
openssl(['ca', '-selfsign', '-batch', '-config', caConfig, '-keyfile', key, '-cert', cert,
  '-in', request, '-out', expiredCert, '-startdate', '20000101000000Z', '-enddate', '20010101000000Z', '-extensions', 'extensions']);
const expired = archive(expiredCert);
const bin = join(work, 'bin');
mkdirSync(bin);
const gh = join(bin, 'gh');
writeFileSync(gh, `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
const data = fs.readFileSync(0);
fs.appendFileSync(process.env.FAKE_GH_LOG, JSON.stringify({args, inputLength: data.length}) + '\\n');
if (args.includes(process.env.FAIL_REPO || 'no-match')) { console.error('secret-sentinel server error'); process.exit(1); }
const stateFile = process.env.FAKE_ISSUE_STATE || process.env.FAKE_GH_LOG + '.issues';
const issues = fs.existsSync(stateFile) ? JSON.parse(fs.readFileSync(stateFile, 'utf8')) : [];
if (args[0] === 'api') { console.log(JSON.stringify([issues])); process.exit(0); }
if (args[0] === 'issue') {
  if (args[1] === 'create') issues.push({number: issues.length + 1, state: 'open', body: data.toString()});
  else {
    const issue = issues.find(x => x.number === Number(args[2]));
    if (args[1] === 'edit') issue.body = data.toString();
    if (args[1] === 'close') issue.state = 'closed';
    if (args[1] === 'reopen') issue.state = 'open';
  }
  fs.writeFileSync(stateFile, JSON.stringify(issues));
}
`);
chmodSync(gh, 0o755);
let counter = 0;
function run(operation, extra = [], credentials = source, env = {}, config = { repositories: ['example-owner/first', 'example-owner/second'] }) {
  const log = join(work, `gh-${++counter}.jsonl`);
  const file = join(work, `repositories-${counter}.json`);
  writeFileSync(file, JSON.stringify(config));
  const result = spawnSync('python3', [join(root, 'bin/dist-tools'), 'apple', 'credentials', operation,
    ...(operation === 'sync' ? ['--config', file] : []), ...extra], {
    input: typeof credentials === 'string' ? credentials : JSON.stringify(credentials), encoding: 'utf8',
    env: { ...process.env, PATH: bin + delimiter + process.env.PATH, FAKE_GH_LOG: log, ...env }, timeout: 15_000,
  });
  const calls = existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse) : [];
  return { ...result, calls };
}

test('inspect validates a real synthetic PKCS12 and reports only limited metadata', () => {
  const result = run('inspect');
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.inspection.valid_now, true);
  assert.equal(report.inspection.certificate_kind, 'Developer ID Application');
  assert.ok(report.inspection.days_remaining > 360);
  assert.deepEqual(result.calls, []);
  assert.doesNotMatch(result.stdout, /TESTTEAM01|Example Fixture|test@example|synthetic-password|notary-secret-sentinel/);
});

test('inspect accepts a legacy-encrypted macOS-style PKCS12 without changing it', () => {
  const help = spawnSync('openssl', ['pkcs12', '-help'], { encoding: 'utf8' });
  const legacy = archive(cert, [
    ...((help.stdout + help.stderr).includes('-legacy') ? ['-legacy'] : []),
    '-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-RC2-40',
  ]);
  const result = run('inspect', [], { ...source, MACOS_CODE_SIGN_P12_BASE64: legacy });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).inspection.valid_now, true);
  assert.deepEqual(result.calls, []);
});

test('dry run validates the source and lists targets/names with zero GitHub calls', () => {
  const result = run('sync', ['--all', '--dry-run']);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.dry_run, true);
  assert.equal(report.targets.length, 2);
  assert.ok(report.secret_names.includes('MACOS_CODE_SIGN_P12_PASSWORD'));
  assert.deepEqual(result.calls, []);
  assert.doesNotMatch(result.stdout, /synthetic-password|notary-secret-sentinel|TESTTEAM01|test@example/);
});

for (const [description, credentials] of [
  ['bad password', { ...source, MACOS_CODE_SIGN_P12_PASSWORD: 'wrong-password' }],
  ['bad base64', { ...source, MACOS_CODE_SIGN_P12_BASE64: '!!!' }],
  ['wrong team', { ...source, APPLE_TEAM_ID: 'OTHERTEAM1' }],
  ['expired certificate', { ...source, MACOS_CODE_SIGN_P12_BASE64: expired }],
  ['mixed auth', { ...source, APPLE_NOTARY_API_KEY: 'invalid-secret-sentinel' }],
  ['missing password', { ...source, APPLE_NOTARY_PASSWORD: '' }],
  ['unknown field', { ...source, GH_TOKEN: 'invalid-secret-sentinel' }],
  ['malformed JSON', '{bad-json-secret-sentinel'],
]) {
  test(`sync rejects ${description} before any writes`, () => {
    const result = run('sync', ['--all'], credentials);
    assert.notEqual(result.status, 0);
    assert.deepEqual(result.calls, []);
    assert.doesNotMatch(result.stdout + result.stderr, /secret-sentinel|wrong-password|synthetic-password/);
  });
}

test('inspect reports expired credentials without allowing sync', () => {
  const result = run('inspect', [], { ...source, MACOS_CODE_SIGN_P12_BASE64: expired });
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stdout).inspection.valid_now, false);
});

test('sync rejects a certificate without the Apple Developer ID type extension', () => {
  const other = join(work, 'other.pem');
  openssl(['req', '-new', '-x509', '-key', key, '-subj', '/CN=Developer ID Application: Example Fixture/OU=TESTTEAM01', '-days', '365', '-out', other]);
  const result = run('sync', ['--all'], { ...source, MACOS_CODE_SIGN_P12_BASE64: archive(other) });
  assert.notEqual(result.status, 0);
  assert.deepEqual(result.calls, []);
});

test('sync rejects a certificate-only PKCS12 without a private key', () => {
  const file = join(work, 'no-private.p12');
  openssl(['pkcs12', '-export', '-nokeys', '-in', cert, '-out', file, '-passout', 'pass:synthetic-password']);
  const result = run('sync', ['--all'], { ...source, MACOS_CODE_SIGN_P12_BASE64: readFileSync(file).toString('base64') });
  assert.notEqual(result.status, 0);
  assert.deepEqual(result.calls, []);
});

for (const selection of [[], ['--repo', 'example-owner/not-allowlisted']]) {
  test(`sync requires explicit allowlisted targets: ${selection}`, () => {
    const result = run('sync', selection);
    assert.notEqual(result.status, 0);
    assert.deepEqual(result.calls, []);
  });
}

test('sync rejects duplicate and option-like repositories in config', () => {
  for (const repositories of [['example-owner/first', 'EXAMPLE-OWNER/FIRST'], ['--bad/repo']]) {
    const result = run('sync', ['--all'], source, {}, { repositories });
    assert.notEqual(result.status, 0);
    assert.deepEqual(result.calls, []);
  }
});

test('sync sends secrets over stdin, reports partial failure, and supports rerunning', () => {
  const failed = run('sync', ['--all'], source, { FAIL_REPO: 'example-owner/first' });
  assert.equal(failed.status, 1);
  assert.deepEqual(JSON.parse(failed.stdout).results.map(x => x.status), ['failed', 'updated']);
  assert.doesNotMatch(failed.stdout + failed.stderr, /secret-sentinel/);
  const retry = run('sync', ['--all']);
  const again = run('sync', ['--all']);
  assert.equal(retry.status, 0, retry.stderr);
  assert.equal(again.status, 0, again.stderr);
  assert.deepEqual(retry.calls, again.calls);
  assert.equal(retry.calls.length, 14);
  for (const call of retry.calls) {
    assert.ok(call.inputLength > 0);
    assert.doesNotMatch(call.args.join(' '), /synthetic-password|notary-secret-sentinel|test@example|--body/);
  }
  assert.ok(retry.calls.some(x => x.args[0] === 'secret' && x.args[2] === 'APPLE_TEAM_ID'));
  assert.ok(retry.calls.some(x => x.args[0] === 'variable' && x.args[2] === 'APPLE_TEAM_ID'));
});

test('API source validates the private key and synchronises only that auth mode', () => {
  const api = openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256']);
  const { APPLE_NOTARY_APPLE_ID, APPLE_NOTARY_PASSWORD, ...signing } = source;
  const credentials = { ...signing, APPLE_NOTARY_AUTH_MODE: 'api-individual', APPLE_NOTARY_API_KEY: api, APPLE_NOTARY_KEY_ID: 'TESTKEY001' };
  const result = run('sync', ['--repo', 'example-owner/first'], credentials);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.calls.some(x => x.args.includes('APPLE_NOTARY_API_KEY')), true);
  assert.equal(result.calls.some(x => x.args.includes('APPLE_NOTARY_APPLE_ID')), false);
  assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE KEY|TESTKEY001/);
  const invalid = run('sync', ['--all'], { ...credentials, APPLE_NOTARY_API_KEY: 'invalid-secret-sentinel' });
  assert.notEqual(invalid.status, 0);
  assert.deepEqual(invalid.calls, []);
});

test('health thresholds handle 90/60/30-day warnings, expiry, and future validity', () => {
  const cases = [91, 90, 61, 60, 31, 30, 0, -1].map(days => ({valid_now: days >= 0, days_remaining: days}));
  cases.push({valid_now: false, days_remaining: 365});
  const code = 'import json,sys; sys.path.insert(0,sys.argv[1]); from health import expiry_problem; print(json.dumps([expiry_problem(x) for x in json.load(sys.stdin)]))';
  const result = spawnSync('python3', ['-c', code, join(root, 'cli')], { input: JSON.stringify(cases), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), [null, 'expires-within-90-days', 'expires-within-90-days',
    'expires-within-60-days', 'expires-within-60-days', 'expires-within-30-days', 'expires-within-30-days', 'expired', 'not-yet-valid']);
});

test('routine health requires only signing credentials and makes no GitHub calls without an issue destination', () => {
  const { MACOS_CODE_SIGN_P12_BASE64, MACOS_CODE_SIGN_P12_PASSWORD, APPLE_TEAM_ID } = source;
  const result = run('health', [], { MACOS_CODE_SIGN_P12_BASE64, MACOS_CODE_SIGN_P12_PASSWORD, APPLE_TEAM_ID });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {checks: {signing: null}, notary_checked: false});
  assert.deepEqual(result.calls, []);
});

test('health maintains one issue, stays quiet on unchanged problems, closes on recovery and reopens on recurrence', () => {
  const state = join(work, 'health-issues.json');
  const options = ['--issue-repo', 'example-owner/health'];
  const env = { FAKE_ISSUE_STATE: state };
  const bad = { ...source, MACOS_CODE_SIGN_P12_BASE64: expired };
  const first = run('health', options, bad, env);
  assert.equal(first.status, 0, first.stderr);
  assert.ok(first.calls.some(x => x.args[1] === 'create'));
  const second = run('health', options, bad, env);
  assert.equal(second.calls.length, 1);
  assert.equal(second.calls[0].args[0], 'api');
  const recovery = run('health', options, source, env);
  assert.equal(recovery.status, 0, recovery.stderr);
  assert.ok(recovery.calls.some(x => x.args[1] === 'close'));
  const recurrence = run('health', options, bad, env);
  assert.ok(recurrence.calls.some(x => x.args[1] === 'reopen'));
  const issues = JSON.parse(readFileSync(state, 'utf8'));
  assert.equal(issues.length, 1);
  assert.doesNotMatch(issues[0].body, /TESTTEAM01|Example Fixture|test@example|synthetic-password|secret-sentinel/);
});

test('invalid health input reports a generic problem without leaking raw input', () => {
  const result = run('health', [], '{invalid-secret-sentinel');
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stdout).checks.signing, 'invalid-credential-source');
  assert.doesNotMatch(result.stdout + result.stderr, /invalid-secret-sentinel/);
});

test('read-only notary health refuses a workstation', () => {
  const result = run('health', ['--check-notary'], source, { GITHUB_ACTIONS: 'false', RUNNER_ENVIRONMENT: 'self-hosted' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /disposable GitHub-hosted/);
  assert.deepEqual(result.calls, []);
});

test('health reports a notary failure separately and closes that issue after auth recovery', () => {
  const state = join(work, 'notary-health-issues.json');
  const log = join(work, 'notary-health-gh.jsonl');
  const code = `import sys
sys.path.insert(0, sys.argv[1])
import health
health.notary_authenticates = lambda source: sys.argv[2] == 'success'
raise SystemExit(health.check(sys.stdin, issue_repo='example-owner/health', check_notary=True))
`;
  for (const outcome of ['failure', 'failure', 'success']) {
    const result = spawnSync('python3', ['-c', code, join(root, 'cli'), outcome], {
      input: JSON.stringify(source), encoding: 'utf8',
      env: { ...process.env, PATH: bin + delimiter + process.env.PATH, FAKE_GH_LOG: log, FAKE_ISSUE_STATE: state },
    });
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.notary_checked, true);
    assert.equal(report.checks.signing, null);
    assert.equal(report.checks['notary-auth'], outcome === 'success' ? null : 'authentication-or-import-failed');
  }
  const issues = JSON.parse(readFileSync(state, 'utf8'));
  assert.equal(issues.length, 1);
  assert.equal(issues[0].state, 'closed');
  const calls = readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(calls.filter(x => x.args[1] === 'create').length, 1);
  assert.equal(calls.filter(x => x.args[1] === 'edit').length, 0);
});

test('health updates an existing issue only when its threshold changes', () => {
  const state = join(work, 'threshold-issues.json');
  const log = join(work, 'threshold-gh.jsonl');
  const code = 'import sys; sys.path.insert(0,sys.argv[1]); from health import update_issue; update_issue("example-owner/health", "signing", sys.argv[2])';
  for (const problem of ['expires-within-90-days', 'expires-within-90-days', 'expires-within-60-days']) {
    const result = spawnSync('python3', ['-c', code, join(root, 'cli'), problem], {
      encoding: 'utf8', env: { ...process.env, PATH: bin + delimiter + process.env.PATH,
        FAKE_GH_LOG: log, FAKE_ISSUE_STATE: state },
    });
    assert.equal(result.status, 0, result.stderr);
  }
  const calls = readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(calls.filter(x => x.args[1] === 'create').length, 1);
  assert.equal(calls.filter(x => x.args[1] === 'edit').length, 1);
  assert.equal(JSON.parse(readFileSync(state, 'utf8')).length, 1);
});

test('health still fails when its notification issue cannot be maintained', () => {
  const result = run('health', ['--issue-repo', 'example-owner/health'],
    { ...source, MACOS_CODE_SIGN_P12_BASE64: expired }, { FAIL_REPO: 'example-owner/health' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /GitHub operation failed/);
  assert.doesNotMatch(result.stderr, /secret-sentinel/);
});
