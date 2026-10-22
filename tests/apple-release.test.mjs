import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, test } from "node:test";

const root = new URL("../", import.meta.url).pathname;
const directories = [];
afterEach(() => {
  for (const path of directories.splice(0))
    rmSync(path, { recursive: true, force: true });
});
const fakeTool = `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const tool = path.basename(process.argv[1]);
const args = process.argv.slice(2);
const op = args.slice(0, 2).join(' ');
const log = (value) => fs.appendFileSync(process.env.FAKE_LOG, JSON.stringify(value) + '\\n');
log({ tool, args, operation: tool === 'xcrun' ? op : args[0], passwordInEnvironment: !!process.env.APPLE_NOTARY_PASSWORD, apiKeyInEnvironment: !!process.env.APPLE_NOTARY_API_KEY });
if (tool === 'xcodebuild') { console.log('Xcode ' + (process.env.FAKE_XCODE_VERSION || '26.0')); process.exit(0); }
if (tool === 'codesign') {
  if (process.env.FAKE_SIGNATURE_FAILURE || (args.at(-1).endsWith('.dmg') && process.env.FAKE_DMG_SIGNATURE_FAILURE) || (args.includes('--check-notarization') && process.env.FAKE_NOTARIZATION_FAILURE)) process.exit(1);
  if (args.includes('--force') && fs.statSync(args.at(-1)).isDirectory()) {
    const resources = path.join(args.at(-1), 'Contents/_CodeSignature');
    fs.mkdirSync(resources, { recursive: true });
    fs.writeFileSync(path.join(resources, 'CodeResources'), 'public-signature-resources');
  }
  process.exit(0);
}
if (tool === 'xcrun') {
  if (op === 'notarytool store-credentials') {
    const key = args.includes('--key') ? args[args.indexOf('--key') + 1] : null;
    if (key) log({ tool: 'key-file-check', path: key, mode: fs.statSync(key).mode & 0o777, directoryMode: fs.statSync(path.dirname(key)).mode & 0o777 });
    if (process.env.FAKE_AUTH_FAILURE) { console.error(key ? fs.readFileSync(key, 'utf8') : args[args.indexOf('--password') + 1]); process.exit(1); }
    process.exit(0);
  }
  if (op === 'notarytool submit') {
    if (process.env.FAKE_STATUS === 'malformed') { console.log('bad json'); process.exit(1); }
    const status = args[2].endsWith('.dmg') ? (process.env.FAKE_DMG_STATUS || process.env.FAKE_STATUS) : process.env.FAKE_STATUS;
    console.log(JSON.stringify({ id: process.env.FAKE_SUBMISSION_ID || '12345678-1234-1234-1234-123456789012', status }));
    process.exit(process.env.FAKE_SUBMIT_FAILURE || process.env.FAKE_STATUS === 'In Progress' ? 69 : 0);
  }
  if (op === 'notarytool log') {
    fs.writeFileSync(args[args.length - 1], JSON.stringify({ issues: [{ code: 4000, message: 'Rejected test signature' }] }));
    process.exit(0);
  }
  if (op === 'stapler staple') {
    if (process.env.FAKE_STAPLE_FAILURE || (args[2].endsWith('.dmg') && process.env.FAKE_DMG_STAPLE_FAILURE)) process.exit(1);
    const counter = path.join(process.env.RUNNER_TEMP, 'staple-attempts');
    const attempt = fs.existsSync(counter) ? Number(fs.readFileSync(counter, 'utf8')) + 1 : 1;
    fs.writeFileSync(counter, String(attempt));
    if (attempt <= Number(process.env.FAKE_STAPLE_LOOKUP_FAILURES || 0)) process.exit(68);
    if (fs.statSync(args[2]).isDirectory()) {
      fs.writeFileSync(path.join(args[2], '.ticket'), 'ticket');
      fs.mkdirSync(path.join(args[2], 'Contents'), { recursive: true });
      fs.writeFileSync(path.join(args[2], 'Contents/CodeResources'), 'public-notary-ticket');
    } else fs.appendFileSync(args[2], '-ticket');
    process.exit(0);
  }
  if (op === 'stapler validate') {
    if (process.env.FAKE_VALIDATE_FAILURE || (args[2].endsWith('.dmg') && process.env.FAKE_DMG_VALIDATE_FAILURE)) process.exit(65);
    const counter = path.join(process.env.RUNNER_TEMP, 'validate-attempts');
    const attempt = fs.existsSync(counter) ? Number(fs.readFileSync(counter, 'utf8')) + 1 : 1;
    fs.writeFileSync(counter, String(attempt));
    if (attempt <= Number(process.env.FAKE_VALIDATE_LOOKUP_FAILURES || 0)) process.exit(68);
    const valid = fs.statSync(args[2]).isDirectory() ? fs.existsSync(path.join(args[2], '.ticket')) : fs.readFileSync(args[2], 'utf8').includes('-ticket');
    process.exit(valid ? 0 : 1);
  }
}
if (tool === 'ditto') {
  const source = args[args.length - 2];
  if (!args.includes('-c')) fs.cpSync(source, args.at(-1), { recursive: true });
  else fs.writeFileSync(args.at(-1), fs.existsSync(path.join(source, '.ticket')) ? 'archive-with-ticket' : 'archive-without-ticket');
  process.exit(0);
}
if (tool === 'hdiutil') {
  if (args[0] === 'create') {
    if (process.env.FAKE_DMG_CREATE_FAILURE) process.exit(1);
    const stage = args[args.indexOf('-srcfolder') + 1];
    const app = fs.readdirSync(stage).find(name => name.endsWith('.app'));
    log({ tool: 'disk-image-content', stapledApp: !!app && fs.existsSync(path.join(stage, app, '.ticket')), applicationsLink: fs.readlinkSync(path.join(stage, 'Applications')), mode: fs.statSync(stage).mode & 0o777 });
    fs.writeFileSync(args.at(-1), 'disk-image-with-stapled-app');
    process.exit(0);
  }
  if (args[0] === 'verify') process.exit(process.env.FAKE_DMG_VERIFY_FAILURE ? 1 : 0);
}
if (tool === 'spctl') process.exit(process.env.FAKE_GATEKEEPER_FAILURE || (args.includes('open') && process.env.FAKE_DMG_GATEKEEPER_FAILURE) ? 1 : 0);
if (tool === 'unzip') process.exit(process.env.FAKE_ARCHIVE_FAILURE ? 1 : 0);
if (tool === 'sleep' || tool === 'sudo') process.exit(0);
if (tool === 'security') {
  if (args[0] === 'delete-keychain' && process.env.FAKE_CLEANUP_HANG) { setTimeout(() => process.exit(0), 30_000); return; }
  if (args[0] === 'import' && (process.env.FAKE_IMPORT_FAILURE || fs.readFileSync(args[1], 'utf8') !== 'test')) process.exit(1);
  if (args[0] === 'list-keychains' && args.length === 3 && process.env.FAKE_LIST_FAILURE) process.exit(1);
  if (args[0] === 'list-keychains' && args.length === 3 && !process.env.FAKE_EMPTY_KEYCHAINS) console.log('  "/tmp/original.keychain-db"');
  if (args[0] === 'find-identity' && process.env.FAKE_MULTIPLE_IDENTITIES) console.log('  2) BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB \"' + process.env.FAKE_IDENTITY + '\"');
  if (args[0] === 'find-identity') console.log('  1) AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "' + process.env.FAKE_IDENTITY + '"');
  process.exit(0);
}
if (tool === 'probe') {
  console.log(JSON.stringify({ identity: process.env.CODE_SIGN_IDENTITY, hasKeychain: !!process.env.CODE_SIGN_KEYCHAIN,
    leakedCertificateSecret: !!process.env.APPLE_CODE_SIGN_P12_BASE64 || !!process.env.APPLE_CODE_SIGN_P12_PASSWORD }));
  process.exit(0);
}
throw new Error('Unexpected fake tool invocation: ' + tool + ' ' + op);
`;
function fixture(suffix = ".app") {
  const path = realpathSync(mkdtempSync(join(tmpdir(), "dist-tools-notary-test-")));
  directories.push(path);
  const bin = join(path, "bin");
  mkdirSync(bin);
  for (const name of [
    "xcrun",
    "xcodebuild",
    "codesign",
    "ditto",
    "hdiutil",
    "spctl",
    "unzip",
    "security",
    "probe",
    "sleep",
    "sudo",
  ]) {
    const file = join(bin, name);
    writeFileSync(file, fakeTool);
    chmodSync(file, 0o755);
  }
  const app = join(path, "Example Bundle" + suffix);
  mkdirSync(app);
  const output = join(path, "Example-App.zip");
  writeFileSync(output, "previous-successful-download");
  const log = join(path, "operations.jsonl");
  const env = {
    ...process.env,
    PATH: bin + delimiter + process.env.PATH,
    RUNNER_TEMP: path,
    APPLE_TEAM_ID: "TESTTEAM01",
    GITHUB_ACTIONS: "false",
    FAKE_LOG: log,
    FAKE_STATUS: "Accepted",
  };
  const operations = () =>
    existsSync(log)
      ? readFileSync(log, "utf8")
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line))
      : [];
  return { path, app, output, env, operations };
}
function runNotary(item, extra = {}, bundleId = "com.example.desktop") {
  return spawnSync(
    "bash",
    [
      join(root, "scripts/apple-signing/notarize-app.sh"),
      item.app,
      item.output,
      bundleId,
    ],
    {
      env: { ...item.env, ...extra },
      encoding: "utf8",
      timeout: 10_000,
    },
  );
}

test("notarization staples before rebuilding the downloadable ZIP", () => {
  const item = fixture();
  const result = runNotary(item);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(item.output, "utf8"), "archive-with-ticket");
  const operations = item.operations().map((x) => `${x.tool} ${x.operation}`);
  assert.ok(
    operations.indexOf("xcrun stapler validate") <
      operations.indexOf("spctl --assess"),
  );
  assert.equal(operations.filter((x) => x === "ditto -c").length, 2);
  assert.equal(
    item
      .operations()
      .some((x) => x.operation === "notarytool store-credentials"),
    false,
  );
});

for (const suffix of ['.app', '.plugin']) {
  test(`stapled ${suffix} tickets remain readable after the private credential-file umask`, () => {
    const item = fixture(suffix);
    mkdirSync(join(item.app, 'Contents'), { recursive: true });
    const ticket = join(item.app, 'Contents/CodeResources');
    writeFileSync(ticket, 'previous-ticket', { mode: 0o600 });
    const result = runNotary(item);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(statSync(ticket).mode & 0o777, 0o644);
    assert.equal(readFileSync(ticket, 'utf8'), 'public-notary-ticket');
  });
}
for (const status of ["Invalid", "Rejected", "In Progress", "malformed"]) {
  test(`notarization ${status} preserves the previous download and never staples`, () => {
    const item = fixture();
    const result = runNotary(item, { FAKE_STATUS: status });
    assert.notEqual(result.status, 0);
    assert.equal(
      readFileSync(item.output, "utf8"),
      "previous-successful-download",
    );
    assert.equal(
      item.operations().some((x) => x.operation === "stapler staple"),
      false,
    );
  });
}
test("stapling failure does not replace the previous download", () => {
  const item = fixture();
  assert.notEqual(runNotary(item, { FAKE_STAPLE_FAILURE: "1" }).status, 0);
  assert.equal(
    readFileSync(item.output, "utf8"),
    "previous-successful-download",
  );
  assert.equal(item.operations().filter(x => x.operation === "stapler staple").length, 1);
  assert.equal(item.operations().some(x => x.tool === "sleep"), false);
});
test("transient ticket lookup failures retry stapling without resubmitting", () => {
  const item = fixture();
  const result = runNotary(item, { FAKE_STAPLE_LOOKUP_FAILURES: "2" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(item.output, "utf8"), "archive-with-ticket");
  const calls = item.operations();
  assert.equal(calls.filter(x => x.operation === "stapler staple").length, 3);
  assert.equal(calls.filter(x => x.operation === "notarytool submit").length, 1);
  assert.deepEqual(calls.filter(x => x.tool === "sleep").map(x => x.operation), ["5", "10"]);
});
test("persistent ticket lookup failure stops after four attempts and preserves the download", () => {
  const item = fixture();
  const result = runNotary(item, { FAKE_STAPLE_LOOKUP_FAILURES: "4" });
  assert.equal(result.status, 68, result.stderr);
  assert.equal(readFileSync(item.output, "utf8"), "previous-successful-download");
  const calls = item.operations();
  assert.equal(calls.filter(x => x.operation === "stapler staple").length, 4);
  assert.deepEqual(calls.filter(x => x.tool === "sleep").map(x => x.operation), ["5", "10", "15"]);
  assert.equal(calls.some(x => x.operation === "stapler validate"), false);
  assert.equal(calls.some(x => x.tool === "spctl"), false);
  assert.equal(calls.filter(x => x.tool === "ditto").length, 1);
});
for (const [failures, expectedStatus, attempts] of [["2", 0, 3], ["4", 68, 4]]) {
  test(`validation lookup failures ${expectedStatus === 0 ? "recover" : "stop after four attempts"}`, () => {
    const item = fixture();
    const result = runNotary(item, { FAKE_VALIDATE_LOOKUP_FAILURES: failures });
    assert.equal(result.status, expectedStatus, result.stderr);
    const calls = item.operations();
    assert.equal(calls.filter(x => x.operation === "stapler validate").length, attempts);
    assert.equal(calls.filter(x => x.operation === "stapler staple").length, 1);
    assert.equal(calls.filter(x => x.operation === "notarytool submit").length, 1);
    assert.equal(calls.some(x => x.tool === "spctl"), expectedStatus === 0);
    assert.equal(readFileSync(item.output, "utf8"), expectedStatus === 0 ? "archive-with-ticket" : "previous-successful-download");
    assert.deepEqual(calls.filter(x => x.tool === "sleep").map(x => x.operation), expectedStatus === 0 ? ["5", "10"] : ["5", "10", "15"]);
  });
}
test("invalid ticket validation fails immediately and preserves the download", () => {
  const item = fixture();
  assert.equal(runNotary(item, { FAKE_VALIDATE_FAILURE: "1" }).status, 65);
  assert.equal(readFileSync(item.output, "utf8"), "previous-successful-download");
  assert.equal(item.operations().filter(x => x.operation === "stapler validate").length, 1);
  assert.equal(item.operations().some(x => x.tool === "sleep" || x.tool === "spctl"), false);
});
test("invalid signing identity fails before submission", () => {
  const item = fixture();
  assert.notEqual(runNotary(item, { FAKE_SIGNATURE_FAILURE: "1" }).status, 0);
  assert.equal(
    item.operations().some((x) => x.operation === "notarytool submit"),
    false,
  );
});
test("Gatekeeper failure preserves the previous download after stapling", () => {
  const item = fixture();
  assert.notEqual(runNotary(item, { FAKE_GATEKEEPER_FAILURE: "1" }).status, 0);
  assert.equal(
    readFileSync(item.output, "utf8"),
    "previous-successful-download",
  );
  assert.equal(item.operations().filter((x) => x.tool === "ditto").length, 1);
});
test("CI stores notarization credentials only in its disposable keychain", () => {
  const item = fixture();
  const result = runNotary(item, {
    GITHUB_ACTIONS: "true",
    CODE_SIGN_KEYCHAIN: join(item.path, "temporary.keychain-db"),
    APPLE_NOTARY_APPLE_ID: "test@example.invalid",
    APPLE_NOTARY_PASSWORD: "secret-sentinel",
  });
  assert.equal(result.status, 0, result.stderr);
  const calls = item.operations();
  assert.equal(
    calls.find((x) => x.operation === "notarytool store-credentials")
      .passwordInEnvironment,
    false,
  );
  assert.equal(
    calls.find((x) => x.operation === "notarytool submit")
      .passwordInEnvironment,
    false,
  );
  assert.doesNotMatch(result.stdout + result.stderr, /secret-sentinel/);
});
for (const [identity, accepted] of [
  ["Developer ID Application: Test Person (TESTTEAM01)", true],
  ["Developer ID Application: Other Person (OTHERTEAM1)", false],
  ["Example Self Signed", false],
  ["Apple Distribution: Test Person (TESTTEAM01)", false],
]) {
  test(`CI import ${accepted ? "accepts selected team" : "rejects"}: ${identity}`, () => {
    const item = fixture();
    const result = spawnSync(
      "bash",
      [join(root, "scripts/apple-signing/with-signing-identity.sh"), "probe"],
      {
        env: {
          ...item.env,
          GITHUB_ACTIONS: "true",
          RUNNER_ENVIRONMENT: "github-hosted",
          RUNNER_OS: "macOS",
          APPLE_CODE_SIGN_P12_BASE64: "dGVzdA==",
          APPLE_CODE_SIGN_P12_PASSWORD: "certificate-secret",
          FAKE_IDENTITY: identity,
        },
        encoding: "utf8",
        timeout: 10_000,
      },
    );
    assert.equal(result.status === 0, accepted, result.stderr);
    assert.equal(
      item.operations().some((x) => x.operation === "add-trusted-cert"),
      false,
    );
    assert.equal(
      item.operations().some((x) => x.operation === "delete-keychain"),
      true,
    );
    if (accepted)
      assert.deepEqual(JSON.parse(result.stdout), {
        identity: "A".repeat(40),
        hasKeychain: true,
        leakedCertificateSecret: false,
      });
  });
}
test("CI import refuses a developer workstation", () => {
  const item = fixture();
  const result = spawnSync(
    "bash",
    [join(root, "scripts/apple-signing/with-signing-identity.sh"), "probe"],
    {
      env: item.env,
      encoding: "utf8",
      timeout: 10_000,
    },
  );
  assert.notEqual(result.status, 0);
  assert.deepEqual(item.operations(), []);
});

test("CI import rejects malformed base64 before importing a certificate", () => {
  const item = fixture();
  const result = spawnSync(
    "bash",
    [join(root, "scripts/apple-signing/with-signing-identity.sh"), "probe"],
    {
      env: {
        ...item.env,
        GITHUB_ACTIONS: "true",
        RUNNER_ENVIRONMENT: "github-hosted",
        RUNNER_OS: "macOS",
        APPLE_CODE_SIGN_P12_BASE64: "!!!!",
        APPLE_CODE_SIGN_P12_PASSWORD: "certificate-secret",
      },
      encoding: "utf8",
      timeout: 10_000,
    },
  );
  assert.notEqual(result.status, 0);
  assert.equal(item.operations().some((x) => x.operation === "import"), false);
});

for (const extra of [
  { FAKE_SUBMIT_FAILURE: "1" },
  { FAKE_SUBMISSION_ID: "not-a-submission-id" },
  { FAKE_STATUS: "Unknown" },
  { FAKE_ARCHIVE_FAILURE: "1" },
]) {
  test(`failed submission or archive verification preserves output: ${JSON.stringify(extra)}`, () => {
    const item = fixture();
    const result = runNotary(item, extra);
    assert.notEqual(result.status, 0);
    assert.equal(readFileSync(item.output, "utf8"), "previous-successful-download");
    if (!extra.FAKE_ARCHIVE_FAILURE)
      assert.equal(item.operations().some(x => x.operation === "stapler staple"), false);
  });
}

test("release signs with hardened runtime and timestamp before notarizing", () => {
  const item = fixture();
  const bin = join(item.app, "Contents", "MacOS");
  mkdirSync(bin, { recursive: true });
  const executable = join(bin, "example-app");
  writeFileSync(executable, '#!/bin/sh\n[ "$1" = --check-runtime ]\n');
  chmodSync(executable, 0o755);
  const result = spawnSync("bash", [join(root, "scripts/apple-signing/release-app.sh"), item.app, item.output, "com.example.desktop"], {
    env: { ...item.env, APPLE_POST_SIGN_COMMAND: 'env PATH=/usr/bin:/bin DEVELOPER_DIR=/nonexistent "$APPLE_RELEASE_APP/Contents/MacOS/example-app" --check-runtime', CODE_SIGN_IDENTITY: "A".repeat(40), CODE_SIGN_KEYCHAIN: join(item.path, "temporary.keychain-db") },
    encoding: "utf8", timeout: 10_000,
  });
  assert.equal(result.status, 0, result.stderr);
  const calls = item.operations();
  const signing = calls.find(x => x.tool === "codesign" && x.operation === "--force");
  assert.ok(signing.args.includes("--timestamp"));
  assert.ok(signing.args.includes("runtime"));
  assert.ok(signing.args.includes("--keychain"));
  assert.equal(signing.args.includes("--deep"), false);
  assert.ok(calls.indexOf(signing) < calls.findIndex(x => x.operation === "notarytool submit"));
  assert.equal(readFileSync(item.output, "utf8"), "archive-with-ticket");
});

test("CI deletes its signing keychain when the wrapped command fails", () => {
  const item = fixture();
  const result = spawnSync("bash", [join(root, "scripts/apple-signing/with-signing-identity.sh"), "bash", "-c", "exit 42"], {
    env: { ...item.env, GITHUB_ACTIONS: "true", RUNNER_ENVIRONMENT: "github-hosted", RUNNER_OS: "macOS",
      APPLE_CODE_SIGN_P12_BASE64: "dGVzdA==", APPLE_CODE_SIGN_P12_PASSWORD: "certificate-secret",
      FAKE_IDENTITY: "Developer ID Application: Person (TESTTEAM01)" },
    encoding: "utf8", timeout: 10_000,
  });
  assert.equal(result.status, 42, result.stderr);
  assert.ok(item.operations().some(x => x.operation === "delete-keychain"));
  assert.ok(item.operations().some(x => x.operation === "list-keychains" && x.args.includes("/tmp/original.keychain-db") && x.args.length === 5));
});

for (const bundleId of ['com.example.desktop', 'org.example.universal-app']) {
  test(`shared engine verifies the selected team and ${bundleId} before and after stapling`, () => {
    const item = fixture();
    assert.equal(runNotary(item, {}, bundleId).status, 0);
    const checks = item.operations().filter(x => x.tool === 'codesign');
    assert.equal(checks.length, 2);
    for (const check of checks) {
      const requirement = check.args[check.args.indexOf('--test-requirement') + 1];
      assert.ok(requirement.includes(`identifier "${bundleId}"`));
      assert.ok(requirement.includes('subject.OU] = "TESTTEAM01"'));
      assert.ok(requirement.includes('1.2.840.113635.100.6.1.13'));
      assert.equal(check.passwordInEnvironment, false);
    }
  });
}

for (const [extra, bundleId] of [
  [{ APPLE_TEAM_ID: 'INVALID' }, 'com.example.app'],
  [{}, 'com.example."injected'],
  [{ APPLE_NOTARY_TIMEOUT: '0m' }, 'com.example.app'],
  [{ APPLE_NOTARY_TIMEOUT: '61m' }, 'com.example.app'],
  [{ APPLE_NOTARY_TIMEOUT: '20m --no-wait' }, 'com.example.app'],
]) {
  test(`reject invalid release configuration before invoking tools: ${JSON.stringify([extra, bundleId])}`, () => {
    const item = fixture();
    assert.notEqual(runNotary(item, extra, bundleId).status, 0);
    assert.deepEqual(item.operations(), []);
  });
}

test('notary wait is configurable within its bounds', () => {
  const item = fixture();
  assert.equal(runNotary(item, { APPLE_NOTARY_TIMEOUT: '60m' }).status, 0);
  const submit = item.operations().find(x => x.operation === 'notarytool submit');
  assert.equal(submit.args[submit.args.indexOf('--timeout') + 1], '60m');
});

test('failed credential validation is redacted and removes temporary files', () => {
  const item = fixture();
  const result = runNotary(item, {
    GITHUB_ACTIONS: 'true', CODE_SIGN_KEYCHAIN: '/tmp/test.keychain-db',
    APPLE_NOTARY_APPLE_ID: 'test@example.invalid', APPLE_NOTARY_PASSWORD: 'secret-sentinel',
    FAKE_AUTH_FAILURE: '1',
  });
  assert.notEqual(result.status, 0);
  assert.doesNotMatch(result.stdout + result.stderr, /secret-sentinel/);
  assert.equal(item.operations().some(x => x.operation === 'notarytool submit'), false);
  assert.equal(readdirSync(item.path).some(x => x.startsWith('dist-tools-notary.')), false);
  assert.equal(readFileSync(item.output, 'utf8'), 'previous-successful-download');
});

function runSigning(item, extra = {}) {
  return spawnSync('python3', [join(root, 'scripts/apple-signing/sign-app.py'), item.app], {
    env: { ...item.env, CODE_SIGN_IDENTITY: 'A'.repeat(40), CODE_SIGN_KEYCHAIN: '/tmp/test.keychain-db', ...extra },
    encoding: 'utf8', timeout: 10_000,
  });
}

test('signing failures do not print the selected certificate fingerprint or command', () => {
  const item = fixture();
  const result = runSigning(item, { FAKE_SIGNATURE_FAILURE: '1' });
  assert.notEqual(result.status, 0);
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp('A'.repeat(40)));
  assert.doesNotMatch(result.stdout + result.stderr, /--keychain|--sign/);
});

test('explicit nested signing runs inside-out with separate entitlements and preserves iOS resource bytes', () => {
  const item = fixture();
  const framework = join(item.app, 'Contents/Frameworks/Helper.framework');
  const nested = join(framework, 'Versions/A/Helper');
  mkdirSync(join(framework, 'Versions/A'), { recursive: true });
  writeFileSync(nested, 'macOS executable');
  const resources = join(item.app, 'Contents/Resources');
  mkdirSync(resources, { recursive: true });
  for (const name of ['payload.ipa', 'hashed-sharing.dylib']) writeFileSync(join(resources, name), `original ${name}`);
  const entitlements = join(item.path, 'app.plist');
  writeFileSync(entitlements, '<plist/>');
  const plan = join(item.path, 'plan.json');
  writeFileSync(plan, JSON.stringify([
    { path: 'Contents/Frameworks/Helper.framework/Versions/A/Helper', entitlements },
    { path: 'Contents/Frameworks/Helper.framework' },
  ]));
  const result = runSigning(item, { APPLE_SIGNING_PLAN: plan, APPLE_ENTITLEMENTS: entitlements });
  assert.equal(result.status, 0, result.stderr);
  const calls = item.operations();
  assert.deepEqual(calls.map(x => x.args.at(-1)), [nested, framework, item.app]);
  for (const call of calls) {
    assert.ok(call.args.includes('--timestamp'));
    assert.ok(call.args.includes('runtime'));
    assert.equal(call.args.includes('--deep'), false);
  }
  assert.ok(calls[0].args.includes(entitlements));
  assert.equal(calls[1].args.includes('--entitlements'), false);
  assert.ok(calls[2].args.includes(entitlements));
  for (const name of ['payload.ipa', 'hashed-sharing.dylib']) assert.equal(readFileSync(join(resources, name), 'utf8'), `original ${name}`);
});

for (const plan of [
  {}, [{ path: '.' }], [{ path: '..' }], [{ path: '/tmp' }],
  [{ path: 'missing-code' }], [{ path: 'Contents' }, { path: 'Contents' }],
  [{ path: 'Contents' }, { path: 'Contents/Resources' }],
  [{ path: 'Contents', entitlements: 'missing-entitlements.plist' }],
  [{ path: 'Contents', 'preserve-entitlements': 'true' }],
  [{ path: 'Contents', 'preserve-entitlements': 1 }],
  [{ path: 'Contents', 'preserve-entitlements': true, entitlements: 'other.plist' }],
  [{ path: 'Contents', unexpected: true }],
]) {
  test(`invalid nested signing plan fails before changing signatures: ${JSON.stringify(plan)}`, () => {
    const item = fixture();
    mkdirSync(join(item.app, 'Contents/Resources'), { recursive: true });
    const file = join(item.path, 'plan.json');
    writeFileSync(file, JSON.stringify(plan));
    assert.notEqual(runSigning(item, { APPLE_SIGNING_PLAN: file }).status, 0);
    assert.deepEqual(item.operations(), []);
  });
}

test('nested signing rejects symlink escapes before signing', () => {
  const item = fixture();
  symlinkSync(item.path, join(item.app, 'outside'));
  const plan = join(item.path, 'plan.json');
  writeFileSync(plan, JSON.stringify([{ path: 'outside' }]));
  assert.notEqual(runSigning(item, { APPLE_SIGNING_PLAN: plan }).status, 0);
  assert.deepEqual(item.operations(), []);
});

test('a failed post-sign audit prevents submission and preserves output', () => {
  const item = fixture();
  const result = spawnSync('bash', [join(root, 'scripts/apple-signing/release-app.sh'), item.app, item.output, 'com.example.app'], {
    env: { ...item.env, CODE_SIGN_IDENTITY: 'A'.repeat(40), CODE_SIGN_KEYCHAIN: '/tmp/test.keychain-db',
      APPLE_NOTARY_AUTH_MODE: 'apple-id', APPLE_NOTARY_APPLE_ID: 'test@example.invalid',
      APPLE_NOTARY_PASSWORD: 'secret-sentinel',
      APPLE_POST_SIGN_COMMAND: '[ -z "${APPLE_NOTARY_PASSWORD:-}" ] || exit 99; exit 42' },
    encoding: 'utf8', timeout: 10_000,
  });
  assert.equal(result.status, 42, result.stderr);
  assert.equal(item.operations().some(x => x.operation === 'notarytool submit'), false);
  assert.equal(item.operations()[0].passwordInEnvironment, false);
  assert.equal(readFileSync(item.output, 'utf8'), 'previous-successful-download');
});

for (const extra of [{ FAKE_MULTIPLE_IDENTITIES: '1' }, { FAKE_IMPORT_FAILURE: '1' }, { FAKE_LIST_FAILURE: '1' }]) {
  test(`identity setup aborts safely: ${JSON.stringify(extra)}`, () => {
    const item = fixture();
    const result = spawnSync('bash', [join(root, 'scripts/apple-signing/with-signing-identity.sh'), 'probe'], {
      env: { ...item.env, GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_OS: 'macOS',
        APPLE_CODE_SIGN_P12_BASE64: 'dGVzdA==', APPLE_CODE_SIGN_P12_PASSWORD: 'certificate-secret',
        FAKE_IDENTITY: 'Developer ID Application: Person (TESTTEAM01)', ...extra },
      encoding: 'utf8', timeout: 10_000,
    });
    assert.notEqual(result.status, 0);
    assert.equal(item.operations().some(x => x.tool === 'probe'), false);
    assert.equal(readdirSync(item.path).some(x => x.startsWith('dist-tools-signing.')), false);
    assert.doesNotMatch(result.stdout + result.stderr, /certificate-secret/);
  });
}

for (const environment of ['self-hosted', '']) {
  test(`ticket workaround refuses ${environment || 'local'} runners before privileged commands`, () => {
    const item = fixture();
    const result = spawnSync('bash', [join(root, 'scripts/apple-signing/ticket-network-workaround.sh')], {
      env: { ...item.env, GITHUB_ACTIONS: 'true', RUNNER_OS: 'macOS', RUNNER_ENVIRONMENT: environment },
      encoding: 'utf8', timeout: 10_000,
    });
    assert.notEqual(result.status, 0);
    assert.deepEqual(item.operations(), []);
  });
}

test('opt-in ticket workaround invokes pfctl only on the hosted Mac', () => {
  const item = fixture();
  const result = spawnSync('bash', [join(root, 'scripts/apple-signing/ticket-network-workaround.sh')], {
    env: { ...item.env, GITHUB_ACTIONS: 'true', RUNNER_OS: 'macOS', RUNNER_ENVIRONMENT: 'github-hosted' },
    encoding: 'utf8', timeout: 10_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(item.operations().map(x => [x.tool, ...x.args]), [
    ['sudo', 'pfctl', '-f', '-'], ['sudo', 'pfctl', '-E'],
  ]);
});

test('a stalled keychain deletion is bounded and preserves the wrapped failure status', () => {
  const item = fixture();
  const start = Date.now();
  const result = spawnSync('bash', [join(root, 'scripts/apple-signing/with-signing-identity.sh'), 'bash', '-c', 'exit 42'], {
    env: { ...item.env, GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_OS: 'macOS',
      APPLE_CODE_SIGN_P12_BASE64: 'dGVzdA==', APPLE_CODE_SIGN_P12_PASSWORD: 'certificate-secret',
      FAKE_IDENTITY: 'Developer ID Application: Person (TESTTEAM01)', FAKE_CLEANUP_HANG: '1' },
    encoding: 'utf8', timeout: 22_000,
  });
  assert.equal(result.status, 42, result.stderr);
  assert.match(result.stdout, /cleanup timed out/);
  assert.ok(Date.now() - start < 22_000);
  assert.equal(readdirSync(item.path).some(x => x.startsWith('dist-tools-signing.')), false);
});

test('identity cleanup restores an originally empty keychain search list', () => {
  const item = fixture();
  const result = spawnSync('bash', [join(root, 'scripts/apple-signing/with-signing-identity.sh'), 'probe'], {
    env: { ...item.env, GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_OS: 'macOS',
      APPLE_CODE_SIGN_P12_BASE64: 'dGVzdA==', APPLE_CODE_SIGN_P12_PASSWORD: 'certificate-secret',
      FAKE_IDENTITY: 'Developer ID Application: Person (TESTTEAM01)', FAKE_EMPTY_KEYCHAINS: '1' },
    encoding: 'utf8', timeout: 10_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(item.operations().some(x => x.operation === 'list-keychains' && x.args.length === 4 && x.args.at(-1) === '-s'));
});

test('the composite Action entry point completes the full mocked release and cleanup', () => {
  const item = fixture();
  const action = readFileSync(join(root, 'actions/apple-release/action.yml'), 'utf8');
  const run = action.match(/^      run: \|\n([\s\S]+)$/m)[1].replace(/^        /gm, '');
  const result = spawnSync('bash', ['-euo', 'pipefail', '-c', run], {
    env: { ...item.env, GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_OS: 'macOS',
      DIST_TOOLS_ACTION_PATH: join(root, 'actions/apple-release'), APPLE_RELEASE_APP: item.app,
      APPLE_RELEASE_OUTPUT: item.output, APPLE_RELEASE_BUNDLE_ID: 'com.example.app',
      APPLE_CODE_SIGN_P12_BASE64: 'dGVzdA==', APPLE_CODE_SIGN_P12_PASSWORD: 'certificate-secret',
      APPLE_NOTARY_APPLE_ID: 'test@example.invalid', APPLE_NOTARY_PASSWORD: 'secret-sentinel',
      FAKE_IDENTITY: 'Developer ID Application: Person (TESTTEAM01)' },
    encoding: 'utf8', timeout: 10_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(item.output, 'utf8'), 'archive-with-ticket');
  assert.ok(item.operations().some(x => x.operation === 'delete-keychain'));
  assert.equal(readdirSync(item.path).some(x => /^dist-tools-(signing|notary)\./.test(x)), false);
  assert.doesNotMatch(result.stdout + result.stderr, /certificate-secret|secret-sentinel/);
});

// Generate synthetic signing material at runtime; no private key is checked in.
const generatedKey = spawnSync('openssl', ['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'], { encoding: 'utf8' });
assert.equal(generatedKey.status, 0, 'Synthetic API key generation failed');
const apiCredentials = {
  GITHUB_ACTIONS: 'true', CODE_SIGN_KEYCHAIN: '/tmp/test.keychain-db',
  APPLE_NOTARY_API_KEY: generatedKey.stdout, APPLE_NOTARY_KEY_ID: 'TESTKEY001',
};

for (const mode of ['api-team', 'api-individual']) {
  test(`${mode} registers a restrictive temporary key and removes it before submission`, () => {
    const item = fixture();
    const result = runNotary(item, { ...apiCredentials, APPLE_NOTARY_AUTH_MODE: mode,
      ...(mode === 'api-team' ? { APPLE_NOTARY_ISSUER_ID: '11111111-2222-3333-4444-555555555555' } : {}) });
    assert.equal(result.status, 0, result.stderr);
    const store = item.operations().find(x => x.operation === 'notarytool store-credentials');
    assert.equal(store.args.includes('--issuer'), mode === 'api-team');
    assert.equal(store.args.includes('--apple-id'), false);
    assert.equal(store.args.includes('--team-id'), false);
    assert.ok(store.args.includes('--validate'));
    const key = item.operations().find(x => x.tool === 'key-file-check');
    assert.equal(key.mode, 0o600);
    assert.equal(key.directoryMode, 0o700);
    assert.equal(existsSync(key.path), false);
    for (const call of item.operations()) {
      assert.equal(call.apiKeyInEnvironment ?? false, false);
      assert.equal(call.passwordInEnvironment ?? false, false);
    }
    assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE KEY/);
  });
}

for (const extra of [
  { APPLE_NOTARY_AUTH_MODE: 'api-team' },
  { APPLE_NOTARY_AUTH_MODE: 'api-team', APPLE_NOTARY_ISSUER_ID: 'invalid' },
  { APPLE_NOTARY_AUTH_MODE: 'api-individual', APPLE_NOTARY_ISSUER_ID: '11111111-2222-3333-4444-555555555555' },
  { APPLE_NOTARY_AUTH_MODE: 'api-individual', APPLE_NOTARY_API_KEY: '' },
  { APPLE_NOTARY_AUTH_MODE: 'api-individual', APPLE_NOTARY_KEY_ID: '' },
  { APPLE_NOTARY_AUTH_MODE: 'api-individual', APPLE_NOTARY_PASSWORD: 'secret-sentinel' },
  { APPLE_NOTARY_AUTH_MODE: 'apple-id', APPLE_NOTARY_APPLE_ID: 'test@example.invalid', APPLE_NOTARY_PASSWORD: 'secret-sentinel' },
  { APPLE_NOTARY_AUTH_MODE: 'keychain' },
  { APPLE_NOTARY_AUTH_MODE: 'unknown' },
  {},
]) {
  test(`incomplete or mixed authentication fails before external tools: ${JSON.stringify(Object.keys(extra))}`, () => {
    const item = fixture();
    const result = runNotary(item, { ...apiCredentials, ...extra });
    assert.notEqual(result.status, 0);
    assert.deepEqual(item.operations(), []);
    assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE KEY|secret-sentinel/);
    assert.equal(readFileSync(item.output, 'utf8'), 'previous-successful-download');
  });
}

for (const extra of [{ FAKE_AUTH_FAILURE: '1' }, { APPLE_NOTARY_API_KEY: 'invalid-secret-sentinel' }, { FAKE_XCODE_VERSION: '16.4' }]) {
  test(`API registration failure removes key files and preserves output: ${Object.keys(extra)}`, () => {
    const item = fixture();
    const result = runNotary(item, { ...apiCredentials, APPLE_NOTARY_AUTH_MODE: 'api-individual', ...extra });
    assert.notEqual(result.status, 0);
    assert.equal(item.operations().some(x => x.operation === 'notarytool submit'), false);
    assert.equal(readdirSync(item.path).some(x => x.startsWith('dist-tools-notary.')), false);
    assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE KEY|invalid-secret-sentinel/);
    assert.equal(readFileSync(item.output, 'utf8'), 'previous-successful-download');
  });
}

test('the API Action path imports, audits without auth secrets, submits, and cleans up', () => {
  const item = fixture();
  const action = readFileSync(join(root, 'actions/apple-release/action.yml'), 'utf8');
  const run = action.match(/^      run: \|\n([\s\S]+)$/m)[1].replace(/^        /gm, '');
  const result = spawnSync('bash', ['-euo', 'pipefail', '-c', run], {
    env: { ...item.env, ...apiCredentials, APPLE_NOTARY_AUTH_MODE: 'api-individual',
      RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_OS: 'macOS',
      DIST_TOOLS_ACTION_PATH: join(root, 'actions/apple-release'), APPLE_RELEASE_APP: item.app,
      APPLE_RELEASE_OUTPUT: item.output, APPLE_RELEASE_BUNDLE_ID: 'com.example.app',
      APPLE_CODE_SIGN_P12_BASE64: 'dGVzdA==', APPLE_CODE_SIGN_P12_PASSWORD: 'certificate-secret',
      FAKE_IDENTITY: 'Developer ID Application: Person (TESTTEAM01)',
      APPLE_POST_SIGN_COMMAND: '[ -z "${APPLE_NOTARY_API_KEY:-}" ] && [ -z "${APPLE_NOTARY_KEY_ID:-}" ] && [ -z "${APPLE_CODE_SIGN_P12_PASSWORD:-}" ]' },
    encoding: 'utf8', timeout: 10_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(item.output, 'utf8'), 'archive-with-ticket');
  assert.ok(item.operations().some(x => x.operation === 'delete-keychain'));
  assert.equal(item.operations().find(x => x.tool === 'codesign').apiKeyInEnvironment, false);
  assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE KEY|certificate-secret/);
});


test('plugin release signs nested code first and requires notarization without app assessment', () => {
  const item = fixture('.plugin');
  const core = join(item.app, 'Contents/MacOS/example_core.dylib');
  mkdirSync(join(item.app, 'Contents/MacOS'), { recursive: true });
  writeFileSync(core, 'plugin core');
  const plan = join(item.path, 'signing-plan.json');
  writeFileSync(plan, JSON.stringify([{ path: 'Contents/MacOS/example_core.dylib' }]));
  const result = spawnSync('bash', [join(root, 'scripts/apple-signing/release-app.sh'), item.app, item.output, 'com.example.example_plugin'], {
    env: { ...item.env, CODE_SIGN_IDENTITY: 'A'.repeat(40), CODE_SIGN_KEYCHAIN: '/tmp/test.keychain-db', APPLE_SIGNING_PLAN: plan },
    encoding: 'utf8', timeout: 10_000,
  });
  assert.equal(result.status, 0, result.stderr);
  const calls = item.operations();
  assert.deepEqual(calls.filter(x => x.tool === 'codesign' && x.args.includes('--force')).map(x => x.args.at(-1)), [core, item.app]);
  const check = calls.find(x => x.tool === 'codesign' && x.args.includes('--check-notarization'));
  assert.ok(check.args.includes('--verify'));
  assert.ok(check.args.includes('--deep'));
  assert.ok(check.args.includes('--strict'));
  assert.match(check.args[check.args.indexOf('--test-requirement') + 1], /com\.example\.example_plugin.*TESTTEAM01.* and notarized$/);
  assert.ok(calls.findIndex(x => x.operation === 'stapler validate') < calls.indexOf(check));
  assert.equal(calls.some(x => x.tool === 'spctl'), false);
  assert.equal(readFileSync(item.output, 'utf8'), 'archive-with-ticket');
});

test('failed plugin notarization check preserves the previous output', () => {
  const item = fixture('.plugin');
  const result = runNotary(item, { FAKE_NOTARIZATION_FAILURE: '1' }, 'com.example.example_plugin');
  assert.notEqual(result.status, 0);
  assert.equal(readFileSync(item.output, 'utf8'), 'previous-successful-download');
});

test('unsupported bundle types fail before signing or notarization', () => {
  const item = fixture('.framework');
  assert.notEqual(runSigning(item).status, 0);
  assert.notEqual(runNotary(item).status, 0);
  assert.deepEqual(item.operations(), []);
});

test('nested vendor entitlements are preserved only for explicitly marked targets', () => {
  const item = fixture();
  const helper = join(item.app, 'Contents/Helpers/Updater.xpc');
  mkdirSync(helper, { recursive: true });
  const plan = join(item.path, 'plan.json');
  writeFileSync(plan, JSON.stringify([{ path: 'Contents/Helpers/Updater.xpc', 'preserve-entitlements': true }]));
  const result = runSigning(item, { APPLE_SIGNING_PLAN: plan });
  assert.equal(result.status, 0, result.stderr);
  const calls = item.operations();
  assert.deepEqual(calls.map(x => x.args.at(-1)), [helper, item.app]);
  assert.ok(calls[0].args.includes('--preserve-metadata=entitlements'));
  assert.equal(calls[0].args.includes('--entitlements'), false);
  assert.equal(calls[1].args.includes('--preserve-metadata=entitlements'), false);
});

function runRelease(item, extra = {}) {
  return spawnSync('bash', [join(root, 'scripts/apple-signing/release-app.sh'), item.app, item.output, 'com.example.desktop'], {
    env: { ...item.env, CODE_SIGN_IDENTITY: 'A'.repeat(40), CODE_SIGN_KEYCHAIN: '/tmp/test.keychain-db', ...extra },
    encoding: 'utf8', timeout: 10_000,
  });
}

test('optional DMG contains the stapled app, is signed and submitted separately, and passes disk-image checks', () => {
  const item = fixture();
  const diskImage = join(item.path, 'Example.dmg');
  const result = runRelease(item, {
    APPLE_RELEASE_DMG: diskImage,
    APPLE_NOTARY_AUTH_MODE: 'apple-id', APPLE_NOTARY_APPLE_ID: 'test@example.invalid', APPLE_NOTARY_PASSWORD: 'secret-sentinel',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(item.output, 'utf8'), 'archive-with-ticket');
  assert.equal(readFileSync(diskImage, 'utf8'), 'disk-image-with-stapled-app-ticket');
  const calls = item.operations();
  const submissions = calls.filter(x => x.operation === 'notarytool submit');
  assert.equal(submissions.length, 2);
  assert.ok(submissions[0].args[2].endsWith('.zip'));
  assert.ok(submissions[1].args[2].endsWith('.dmg'));
  const content = calls.find(x => x.tool === 'disk-image-content');
  assert.equal(content.stapledApp, true);
  assert.equal(content.applicationsLink, '/Applications');
  assert.equal(content.mode, 0o755);
  const signing = calls.find(x => x.tool === 'codesign' && x.args.includes('--force') && x.args.at(-1).endsWith('.dmg'));
  assert.ok(signing.args.includes('--timestamp'));
  assert.ok(signing.args.includes('--identifier'));
  assert.ok(calls.indexOf(signing) < calls.indexOf(submissions[1]));
  const assessment = calls.find(x => x.tool === 'spctl' && x.args.includes('open'));
  assert.ok(assessment.args.includes('context:primary-signature'));
  assert.ok(calls.some(x => x.tool === 'hdiutil' && x.operation === 'verify'));
  for (const call of calls.filter(x => ['codesign', 'hdiutil', 'ditto', 'spctl'].includes(x.tool))) {
    assert.equal(call.passwordInEnvironment, false);
    assert.equal(call.apiKeyInEnvironment, false);
  }
  assert.doesNotMatch(result.stdout + result.stderr, /secret-sentinel/);
  assert.equal(readdirSync(item.path).some(x => /^dist-tools-(dmg|notary)\./.test(x)), false);
});

for (const extra of [
  { FAKE_DMG_CREATE_FAILURE: '1' }, { FAKE_DMG_SIGNATURE_FAILURE: '1' },
  { FAKE_DMG_STATUS: 'Invalid' }, { FAKE_DMG_STAPLE_FAILURE: '1' },
  { FAKE_DMG_VALIDATE_FAILURE: '1' }, { FAKE_DMG_GATEKEEPER_FAILURE: '1' },
  { FAKE_DMG_VERIFY_FAILURE: '1' },
]) {
  test(`DMG failure preserves existing DMG and removes temporary files: ${JSON.stringify(extra)}`, () => {
    const item = fixture();
    const diskImage = join(item.path, 'Example.dmg');
    writeFileSync(diskImage, 'previous-disk-image');
    const result = runRelease(item, { APPLE_RELEASE_DMG: diskImage, ...extra });
    assert.notEqual(result.status, 0);
    assert.equal(readFileSync(diskImage, 'utf8'), 'previous-disk-image');
    assert.equal(readFileSync(item.output, 'utf8'), 'archive-with-ticket');
    assert.doesNotMatch(result.stdout + result.stderr, new RegExp('A'.repeat(40)));
    assert.equal(readdirSync(item.path).some(x => /^dist-tools-(dmg|notary)\./.test(x) || x.startsWith('.dist-tools-notarized.')), false);
  });
}

for (const [suffix, destination] of [
  ['.plugin', 'Example.dmg'], ['.app', 'Example.zip'], ['.app', 'missing/Example.dmg'],
]) {
  test(`invalid DMG destination fails before signing: ${suffix} ${destination}`, () => {
    const item = fixture(suffix);
    assert.notEqual(runRelease(item, { APPLE_RELEASE_DMG: join(item.path, destination) }).status, 0);
    assert.deepEqual(item.operations(), []);
  });
}

for (const suffix of ['.app', '.plugin']) {
  test(`new ${suffix} signature resources remain readable under a private parent umask`, () => {
    const item = fixture(suffix);
    const helper = join(item.app, 'Contents/Helpers/Example.app');
    mkdirSync(helper, { recursive: true });
    const plan = join(item.path, 'signing-plan.json');
    writeFileSync(plan, JSON.stringify([{ path: 'Contents/Helpers/Example.app' }]));
    const result = spawnSync('bash', ['-c', 'umask 077; exec python3 "$@"', '--', join(root, 'scripts/apple-signing/sign-app.py'), item.app], {
      env: { ...item.env, CODE_SIGN_IDENTITY: 'A'.repeat(40), CODE_SIGN_KEYCHAIN: '/tmp/test.keychain-db', APPLE_SIGNING_PLAN: plan },
      encoding: 'utf8', timeout: 10_000,
    });
    assert.equal(result.status, 0, result.stderr);
    for (const bundle of [helper, item.app]) {
      assert.equal(statSync(join(bundle, 'Contents/_CodeSignature')).mode & 0o777, 0o755);
      const resources = join(bundle, 'Contents/_CodeSignature/CodeResources');
      assert.equal(statSync(resources).mode & 0o777, 0o644);
      assert.equal(readFileSync(resources, 'utf8'), 'public-signature-resources');
    }
  });
}
