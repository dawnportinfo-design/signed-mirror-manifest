import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const vector = JSON.parse(
  readFileSync(path.join(repoRoot, 'test-vectors', 'manifest-v1-ed25519.json'), 'utf8'),
);
const ajv = new Ajv2020({ allErrors: true });
addFormats(ajv);
const validateVerifyResult = ajv.compile(
  JSON.parse(readFileSync(path.join(repoRoot, 'schemas', 'verify-result.schema.json'), 'utf8')),
);
const validateInspectResult = ajv.compile(
  JSON.parse(readFileSync(path.join(repoRoot, 'schemas', 'inspect-result.schema.json'), 'utf8')),
);
const validatePublishChecklist = ajv.compile(
  JSON.parse(readFileSync(path.join(repoRoot, 'schemas', 'publish-checklist.schema.json'), 'utf8')),
);

function runCli(args) {
  const result = spawnSync(process.execPath, [path.join(repoRoot, 'dist', 'cli.js'), ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    shell: false,
  });

  if (result.status !== 0) {
    throw new Error(`CLI failed: ${args.join(' ')}\n${result.stderr}`);
  }

  return JSON.parse(result.stdout);
}

function runCliExpectingFailure(args, expectedStatus) {
  const result = spawnSync(process.execPath, [path.join(repoRoot, 'dist', 'cli.js'), ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    shell: false,
  });

  if (result.status !== expectedStatus) {
    throw new Error(`CLI status ${result.status}, expected ${expectedStatus}: ${args.join(' ')}\n${result.stderr}`);
  }

  return JSON.parse(result.stdout);
}

function runCliText(args) {
  const result = spawnSync(process.execPath, [path.join(repoRoot, 'dist', 'cli.js'), ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    shell: false,
  });

  if (result.status !== 0) {
    throw new Error(`CLI failed: ${args.join(' ')}\n${result.stderr}`);
  }

  return result.stdout;
}

const tempDir = mkdtempSync(path.join(os.tmpdir(), 'smm-smoke-'));
const manifestPath = path.join(tempDir, 'signed-manifest.json');
writeFileSync(manifestPath, `${JSON.stringify(vector.signed_manifest, null, 2)}\n`);
const now = '2026-07-08T00:00:00.000Z';

const verification = runCli(['verify', manifestPath, '--policy', 'operational', '--now', now]);
if (!validateVerifyResult(verification)) {
  throw new Error(`verify result schema failed: ${JSON.stringify(validateVerifyResult.errors)}`);
}
if (!verification.ok) {
  throw new Error(`expected verify to pass: ${JSON.stringify(verification)}`);
}
if (verification.checked.policy !== 'operational' || verification.checked.signature_count < 1) {
  throw new Error(`expected verify checked scope to include policy and signatures: ${JSON.stringify(verification)}`);
}
if (verification.checked.valid_operational_signatures < 1) {
  throw new Error(`expected operational signature count in verify checked scope: ${JSON.stringify(verification)}`);
}
if (!verification.public_timeline_summary?.relay_allowed || verification.public_timeline_summary.status !== 'verified') {
  throw new Error(`expected verified public timeline summary: ${JSON.stringify(verification)}`);
}
if (verification.public_timeline_summary.active_mirror_count !== 1) {
  throw new Error(`expected public timeline summary active mirror count: ${JSON.stringify(verification)}`);
}
if (verification.public_timeline_summary.relay_expires_at !== '2026-07-08T00:15:00.000Z') {
  throw new Error(`expected public timeline summary relay expiry: ${JSON.stringify(verification)}`);
}
if (verification.public_timeline_summary.max_age_seconds > 900) {
  throw new Error(`expected tight public timeline summary freshness window: ${JSON.stringify(verification)}`);
}
if (!verification.public_timeline_summary.required_context.some((item) => item.includes('relay_expires_at'))) {
  throw new Error(`expected public timeline summary to mention relay_expires_at: ${JSON.stringify(verification)}`);
}
if (!verification.public_timeline_summary.do_not_include.some((item) => item.includes('origin infrastructure'))) {
  throw new Error(`expected public timeline summary to block infrastructure details: ${JSON.stringify(verification)}`);
}
if (!verification.public_timeline_summary.non_claims.some((item) => item.includes('DDoS mitigation'))) {
  throw new Error(`expected public timeline summary DDoS non-claim: ${JSON.stringify(verification)}`);
}

const expiredVerification = runCliExpectingFailure([
  'verify',
  manifestPath,
  '--policy',
  'operational',
  '--now',
  '2035-01-01T00:00:00.000Z',
], 2);
if (!validateVerifyResult(expiredVerification)) {
  throw new Error(`expired verify result schema failed: ${JSON.stringify(validateVerifyResult.errors)}`);
}
if (expiredVerification.ok || !expiredVerification.errors.includes('manifest expired')) {
  throw new Error(`expected expired verification failure: ${JSON.stringify(expiredVerification)}`);
}
if (expiredVerification.checked.now !== '2035-01-01T00:00:00.000Z') {
  throw new Error(`expected expired verification to record --now: ${JSON.stringify(expiredVerification)}`);
}
if (expiredVerification.public_timeline_summary.relay_allowed || expiredVerification.public_timeline_summary.status !== 'not-verified') {
  throw new Error(`expected expired verification to block public timeline relay: ${JSON.stringify(expiredVerification)}`);
}
if (!expiredVerification.remediation.includes('Refresh expires_at, increase sequence, and re-sign before announcing mirrors.')) {
  throw new Error(`expected expired remediation guidance: ${JSON.stringify(expiredVerification)}`);
}

const inspection = runCli([
  'inspect',
  manifestPath,
  vector.signed_manifest.mirrors[0].url,
  '--policy',
  'operational',
  '--now',
  now,
]);

if (inspection.policy !== 'operational') {
  throw new Error(`unexpected policy: ${inspection.policy}`);
}
if (!validateInspectResult(inspection)) {
  throw new Error(`inspect result schema failed: ${JSON.stringify(validateInspectResult.errors)}`);
}
if (!inspection.verification.ok) {
  throw new Error(`expected inspect verification to pass: ${JSON.stringify(inspection)}`);
}
if (inspection.mirror.status !== 'verified') {
  throw new Error(`expected verified mirror, got ${inspection.mirror.status}`);
}

const unknownInspection = runCli([
  'inspect',
  manifestPath,
  'https://unknown.example',
  '--policy',
  'operational',
  '--now',
  now,
]);
if (!validateInspectResult(unknownInspection)) {
  throw new Error(`unknown inspect result schema failed: ${JSON.stringify(validateInspectResult.errors)}`);
}
if (unknownInspection.mirror.status !== 'unknown') {
  throw new Error(`expected unknown mirror, got ${unknownInspection.mirror.status}`);
}

const publishChecklist = runCli([
  'publish-checklist',
  manifestPath,
  '--policy',
  'operational',
  '--now',
  now,
]);
if (!validatePublishChecklist(publishChecklist)) {
  throw new Error(`publish checklist schema failed: ${JSON.stringify(validatePublishChecklist.errors)}`);
}
if (!publishChecklist.can_publish) {
  throw new Error(`expected publish checklist to pass: ${JSON.stringify(publishChecklist)}`);
}
if (publishChecklist.active_mirrors.length !== 1) {
  throw new Error(`expected one active mirror: ${JSON.stringify(publishChecklist)}`);
}
if (publishChecklist.publication_freshness?.relay_expires_at !== '2026-07-08T00:15:00.000Z') {
  throw new Error(`expected publish checklist relay freshness: ${JSON.stringify(publishChecklist)}`);
}
if (publishChecklist.publication_freshness?.publish_requires_recheck_after_expiry !== true) {
  throw new Error(`expected publish checklist to require recheck after relay expiry: ${JSON.stringify(publishChecklist)}`);
}
if (!publishChecklist.announcement_channel_boundary?.required_before_channel_post?.some((item) => item.includes('publication_freshness.relay_expires_at'))) {
  throw new Error(`expected publish checklist announcement channel freshness boundary: ${JSON.stringify(publishChecklist)}`);
}

const trustHandoff = runCliText([
  'trust-handoff',
  manifestPath,
  '--policy',
  'operational',
  '--now',
  now,
]);
for (const expected of [
  '# Signed Mirror Trust Handoff',
  '## Trust Decision',
  '## Shareable Mirrors',
  '## Do Not Share',
  '## Announcement Channel Boundary',
  'Allowed channel: publisher-controlled canonical website or status page',
  'Relay expires at: 2026-07-08T00:15:00.000Z',
  'Recheck after relay expiry: yes',
  'https://mirror.vector.example',
]) {
  if (!trustHandoff.includes(expected)) {
    throw new Error(`trust handoff missing ${expected}`);
  }
}

console.log('CLI smoke checks passed.');
