import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { after, test } from 'node:test';

const root = new URL('../', import.meta.url).pathname;
const work = mkdtempSync(join(tmpdir(), 'dist-tools-cli-test-'));
after(() => rmSync(work, { recursive: true, force: true }));
const checkout = join(work, 'checkout');
mkdirSync(join(checkout, '.local'), { recursive: true });
mkdirSync(join(checkout, 'scripts/apple-signing'), { recursive: true });
for (const directory of ['bin', 'cli']) cpSync(join(root, directory), join(checkout, directory), { recursive: true });
cpSync(join(root, 'scripts/apple-signing/notary_auth.py'), join(checkout, 'scripts/apple-signing/notary_auth.py'));
const unrelated = join(work, 'unrelated');
mkdirSync(unrelated);
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
`);
chmodSync(gh, 0o755);
let counter = 0;
function run(operation, extra = [], credentials = source, env = {}, config = ['example-owner/first', 'example-owner/second']) {
  const log = join(work, `gh-${++counter}.jsonl`);
  const file = join(checkout, 'repositories.yaml');
  writeFileSync(file, typeof config === 'string' ? config : 'repositories:\n' + config.map(repo => '  - ' + JSON.stringify(repo)).join('\n') + '\n');
  const result = spawnSync('python3', [join(checkout, 'bin/dist-tools'), 'apple', 'credentials', operation, ...extra], {
    input: typeof credentials === 'string' ? credentials : JSON.stringify(credentials), encoding: 'utf8', cwd: unrelated,
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
  const result = run('sync', ['--dry-run']);
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
    const result = run('sync', [], credentials);
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
  const result = run('sync', [], { ...source, MACOS_CODE_SIGN_P12_BASE64: archive(other) });
  assert.notEqual(result.status, 0);
  assert.deepEqual(result.calls, []);
});

test('sync rejects a certificate-only PKCS12 without a private key', () => {
  const file = join(work, 'no-private.p12');
  openssl(['pkcs12', '-export', '-nokeys', '-in', cert, '-out', file, '-passout', 'pass:synthetic-password']);
  const result = run('sync', [], { ...source, MACOS_CODE_SIGN_P12_BASE64: readFileSync(file).toString('base64') });
  assert.notEqual(result.status, 0);
  assert.deepEqual(result.calls, []);
});

test('sync without flags uses the checkout config from any working directory and updates every repo', () => {
  const result = run('sync');
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.deepEqual(report.targets, ['example-owner/first', 'example-owner/second']);
  assert.deepEqual(report.results, report.targets.map(repository => ({ repository, status: 'updated' })));
  assert.deepEqual([...new Set(result.calls.map(call => call.args.at(-1)))], report.targets);
});

test('missing config explains setup and performs no GitHub calls', () => {
  const result = run('sync', ['--config', join(work, 'missing.yaml')]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /repositories.example.yaml/);
  assert.deepEqual(result.calls, []);
});

test('sync rejects duplicate and option-like repositories in config', () => {
  for (const repositories of [['example-owner/first', 'EXAMPLE-OWNER/FIRST'], ['--bad/repo']]) {
    const result = run('sync', [], source, {}, repositories);
    assert.notEqual(result.status, 0);
    assert.deepEqual(result.calls, []);
  }
});

test('sync sends secrets over stdin, reports partial failure, and supports rerunning', () => {
  const failed = run('sync', [], source, { FAIL_REPO: 'example-owner/first' });
  assert.equal(failed.status, 1);
  assert.deepEqual(JSON.parse(failed.stdout).results.map(x => x.status), ['failed', 'updated']);
  assert.match(JSON.parse(failed.stdout).results[0].message, /Check gh authentication and repository access/);
  assert.doesNotMatch(failed.stdout + failed.stderr, /secret-sentinel/);
  const retry = run('sync', []);
  const again = run('sync', []);
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
  const result = run('sync', [], credentials);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.calls.some(x => x.args.includes('APPLE_NOTARY_API_KEY')), true);
  assert.equal(result.calls.some(x => x.args.includes('APPLE_NOTARY_APPLE_ID')), false);
  assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE KEY|TESTKEY001/);
  const invalid = run('sync', [], { ...credentials, APPLE_NOTARY_API_KEY: 'invalid-secret-sentinel' });
  assert.notEqual(invalid.status, 0);
  assert.deepEqual(invalid.calls, []);
});

test('sync infers Apple ID authentication without an explicit mode', () => {
  const { APPLE_NOTARY_AUTH_MODE, ...credentials } = source;
  const result = run('sync', [], credentials);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).inspection.auth_mode, 'apple-id');
});

for (const [mode, extra] of [
  ['api-individual', {}],
  ['api-team', { APPLE_NOTARY_ISSUER_ID: '11111111-2222-3333-4444-555555555555' }],
]) {
  test(`sync infers ${mode} authentication without an explicit mode`, () => {
    const { APPLE_NOTARY_AUTH_MODE, APPLE_NOTARY_APPLE_ID, APPLE_NOTARY_PASSWORD, ...signing } = source;
    const credentials = { ...signing, APPLE_NOTARY_API_KEY: openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256']), APPLE_NOTARY_KEY_ID: 'TESTKEY001', ...extra };
    const result = run('sync', [], credentials);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).inspection.auth_mode, mode);
    assert.ok(result.calls.some(call => call.args.includes('APPLE_NOTARY_API_KEY')));
  });
}

test('inferred auth still rejects mixed credentials before GitHub writes', () => {
  const { APPLE_NOTARY_AUTH_MODE, ...credentials } = source;
  const result = run('sync', [], { ...credentials, APPLE_NOTARY_KEY_ID: 'TESTKEY001' });
  assert.equal(result.status, 1);
  assert.deepEqual(result.calls, []);
});

test('repository YAML accepts plain and quoted names, comments and blank lines', () => {
  const config = '# Repositories\n\nrepositories: # targets\n  - example-owner/first # desktop\n  - \'example-owner/second\'\n';
  const result = run('sync', ['--dry-run'], source, {}, config);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout).targets, ['example-owner/first', 'example-owner/second']);
  assert.deepEqual(result.calls, []);
});

for (const config of ['', 'other:\n  - example-owner/first\n', '- example-owner/first\n', 'repositories:\n  - example-owner/first\n    - example-owner/second\n', 'repositories:\n  - example-owner/first#not-a-comment\n', 'repositories:\n  - !!python/object example-owner/first\n', 'repositories:\n']) {
  test(`invalid repository YAML performs no writes: ${JSON.stringify(config)}`, () => {
    const result = run('sync', [], source, {}, config);
    assert.equal(result.status, 1);
    assert.deepEqual(result.calls, []);
  });
}

const replacement = join(work, 'replacement certificate.p12');
writeFileSync(replacement, Buffer.from(source.MACOS_CODE_SIGN_P12_BASE64, 'base64'));
const expiredArchive = join(work, 'expired-replacement.p12');
writeFileSync(expiredArchive, Buffer.from(expired, 'base64'));
const apiFile = join(work, 'notary key.p8');
const apiKey = openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256']);
writeFileSync(apiFile, apiKey);
const issuer = '11111111-2222-3333-4444-555555555555';

function manage(operation, existing, p12 = replacement, password = 'synthetic-password') {
  const destination = join(checkout, '.local/credentials.json');
  rmSync(destination, { force: true });
  if (existing !== undefined) writeFileSync(destination, JSON.stringify(existing), { mode: 0o644 });
  const before = existsSync(destination) ? readFileSync(destination, 'utf8') : undefined;
  const log = join(work, `management-gh-${++counter}.jsonl`);
  const code = `import builtins,getpass,io,json,sys
sys.path.insert(0,sys.argv[1])
from credentials import main
request=json.load(sys.stdin)
class Terminal(io.StringIO):
    def isatty(self): return True
sys.stdin=Terminal()
getpass.getpass=lambda prompt: request['password']
answers=iter(request['answers'])
builtins.input=lambda prompt: next(answers)
raise SystemExit(main(sys.argv[2:]))
`;
  const result = spawnSync('python3', ['-c', code, join(checkout, 'cli'), 'apple', 'credentials', operation], {
    cwd: unrelated, encoding: 'utf8', timeout: 15_000,
    input: JSON.stringify({ password, answers: [p12, ...(operation === 'create' ? [apiFile, 'TESTTEAM01', 'TESTKEY001', issuer] : [])] }),
    env: { ...process.env, PATH: bin + delimiter + process.env.PATH, FAKE_GH_LOG: log },
  });
  assert.equal(existsSync(log), false, 'Credential management must not contact GitHub');
  assert.doesNotMatch(result.stdout + result.stderr, /synthetic-password|TESTTEAM01|TESTKEY001|PRIVATE KEY|notary-secret-sentinel/);
  return { ...result, destination, before };
}

test('create without arguments prompts for paths containing spaces and imports private JSON', () => {
  const result = manage('create');
  assert.equal(result.status, 0, result.stderr);
  const actual = JSON.parse(readFileSync(result.destination, 'utf8'));
  assert.deepEqual(actual, {
    MACOS_CODE_SIGN_P12_BASE64: source.MACOS_CODE_SIGN_P12_BASE64,
    MACOS_CODE_SIGN_P12_PASSWORD: source.MACOS_CODE_SIGN_P12_PASSWORD,
    APPLE_TEAM_ID: 'TESTTEAM01', APPLE_NOTARY_API_KEY: apiKey,
    APPLE_NOTARY_KEY_ID: 'TESTKEY001', APPLE_NOTARY_ISSUER_ID: issuer,
  });
  assert.equal(statSync(result.destination).mode & 0o777, 0o600);
});

test('create refuses to overwrite an existing credential export', () => {
  const result = manage('create', source);
  assert.equal(result.status, 1);
  assert.equal(readFileSync(result.destination, 'utf8'), result.before);
});

test('create with an expired certificate leaves no credential JSON', () => {
  const result = manage('create', undefined, expiredArchive);
  assert.equal(result.status, 1);
  assert.equal(existsSync(result.destination), false);
});

for (const auth of [
  source,
  { APPLE_TEAM_ID: 'TESTTEAM01', APPLE_NOTARY_API_KEY: apiKey, APPLE_NOTARY_KEY_ID: 'TESTKEY001', APPLE_NOTARY_ISSUER_ID: issuer },
]) {
  test(`renew without arguments prompts for the replacement and preserves ${auth.APPLE_NOTARY_API_KEY ? 'API' : 'Apple ID'} credentials`, () => {
    const previous = { ...auth, MACOS_CODE_SIGN_P12_BASE64: expired, MACOS_CODE_SIGN_P12_PASSWORD: 'previous-export-password' };
    const result = manage('renew', previous);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(readFileSync(result.destination, 'utf8')), {
      ...previous, MACOS_CODE_SIGN_P12_BASE64: source.MACOS_CODE_SIGN_P12_BASE64,
      MACOS_CODE_SIGN_P12_PASSWORD: source.MACOS_CODE_SIGN_P12_PASSWORD,
    });
    assert.equal(statSync(result.destination).mode & 0o777, 0o600);
  });
}

for (const [description, existing, p12, password] of [
  ['wrong export password', source, replacement, 'wrong-password-sentinel'],
  ['expired replacement', source, expiredArchive, 'synthetic-password'],
  ['different team', { ...source, APPLE_TEAM_ID: 'OTHERTEAM1' }, replacement, 'synthetic-password'],
]) {
  test(`failed renewal preserves the original file: ${description}`, () => {
    const result = manage('renew', existing, p12, password);
    assert.equal(result.status, 1);
    assert.equal(readFileSync(result.destination, 'utf8'), result.before);
    assert.equal(statSync(result.destination).mode & 0o777, 0o644);
  });
}

test('sync with empty redirected input explains how to provide credentials without GitHub calls', () => {
  const result = run('sync', [], '');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /No credential JSON received/);
  assert.match(result.stderr, /< .local\/credentials.json/);
  assert.deepEqual(result.calls, []);
});

const interactiveCases = ['sync', 'inspect'].flatMap(operation =>
  ['default', 'custom', 'missing'].map(choice => ({ operation, choice })));
for (const { operation, choice } of interactiveCases) {
  test(`interactive ${operation} prompts for the credential file: ${choice}`, () => {
    writeFileSync(join(checkout, 'repositories.yaml'), 'repositories:\n  - example-owner/first\n');
    const file = choice === 'default' ? join(checkout, '.local/credentials.json') : join(work, `selected credentials-${choice}.json`);
    if (choice !== 'missing') writeFileSync(file, JSON.stringify(source));
    const log = join(work, `interactive-${operation}-${++counter}.jsonl`);
    const code = `import builtins,io,sys
sys.path.insert(0,sys.argv[1])
from credentials import main
class Terminal(io.StringIO):
    def isatty(self): return True
    def read(self,*args): raise AssertionError('Must not wait for raw JSON on a terminal')
sys.stdin=Terminal()
def choose(prompt):
    assert 'Credential JSON path' in prompt
    return sys.argv[2]
builtins.input=choose
raise SystemExit(main(['apple','credentials',sys.argv[3]]))
`;
    const result = spawnSync('python3', ['-c', code, join(checkout, 'cli'), choice === 'default' ? '' : file, operation], {
      cwd: unrelated, encoding: 'utf8', timeout: 15_000,
      env: { ...process.env, PATH: bin + delimiter + process.env.PATH, FAKE_GH_LOG: log },
    });
    assert.doesNotMatch(result.stdout + result.stderr, /synthetic-password|notary-secret-sentinel|TESTTEAM01/);
    if (choice === 'missing') {
      assert.equal(result.status, 1);
      assert.match(result.stderr, /Credential JSON file not found/);
      assert.equal(existsSync(log), false);
    } else {
      assert.equal(result.status, 0, result.stderr);
      if (operation === 'sync') {
        assert.deepEqual(JSON.parse(result.stdout).results, [{ repository: 'example-owner/first', status: 'updated' }]);
        assert.ok(existsSync(log));
      } else {
        assert.equal(JSON.parse(result.stdout).inspection.valid_now, true);
        assert.equal(existsSync(log), false);
      }
    }
  });
}

test('inspect does not apply GitHub secret-size limits, while sync still rejects oversized secrets', () => {
  const credentials = { ...source, APPLE_NOTARY_PASSWORD: 'x'.repeat(49 * 1024) };
  const inspected = run('inspect', [], credentials);
  assert.equal(inspected.status, 0, inspected.stderr);
  assert.deepEqual(inspected.calls, []);
  const synced = run('sync', [], credentials);
  assert.equal(synced.status, 1);
  assert.match(synced.stderr, /secret size limit/);
  assert.deepEqual(synced.calls, []);
});

test('ending an interactive prompt with Ctrl-D exits cleanly', () => {
  const code = `import builtins,io,sys
sys.path.insert(0,sys.argv[1])
from credentials import main
class Terminal(io.StringIO):
    def isatty(self): return True
sys.stdin=Terminal()
def cancel(prompt): raise EOFError
builtins.input=cancel
raise SystemExit(main(['apple','credentials','inspect']))
`;
  const result = spawnSync('python3', ['-c', code, join(checkout, 'cli')], { encoding: 'utf8', timeout: 2_000 });
  assert.equal(result.status, 1);
  assert.equal(result.stderr.trim(), 'Input cancelled.');
});
