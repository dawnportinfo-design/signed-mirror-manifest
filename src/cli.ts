#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  addKey,
  addMirror,
  buildPublishChecklist,
  inspectMirror,
  payloadSha256,
  renderPublishChecklistMarkdown,
  renderTrustHandoff,
  revokeMirror,
  signManifest,
  unsignedPayload,
  validateManifestBasics,
  verifyManifest,
} from './manifest.js';
import type { ManifestKey, MirrorEntry, MirrorManifest, UnsignedManifest } from './types.js';

function readJson<T>(filePath: string): T {
  return JSON.parse(fs.readFileSync(filePath, 'utf8')) as T;
}

function readFlag(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index === -1 ? undefined : args[index + 1];
}

function requireFlag(args: string[], flag: string): string {
  const value = readFlag(args, flag);

  if (!value) {
    throw new Error(`Missing ${flag}`);
  }

  return value;
}

function usage() {
  console.error(`Usage:
  smm init-key --out <dir>
  smm init-manifest --publisher <name> --origin <url>
  smm add-key <manifest.json> --id <id> --role root|targets|emergency|observer --public-key <key.pem>
  smm add-mirror <manifest.json> --id <id> --url <url> [--type https|onion|ipfs] [--priority 10]
  smm payload <manifest.json>
  smm sign <manifest.json> --private-key <key.pem> --key-id <id> [--append]
  smm verify <manifest.json> [--policy any|operational] [--now <iso8601>]
  smm inspect <manifest.json> <url> [--policy any|operational] [--now <iso8601>]
  smm publish-checklist <manifest.json> [--policy any|operational] [--format json|markdown] [--now <iso8601>]
  smm trust-handoff <manifest.json> [--policy any|operational] [--now <iso8601>]
  smm revoke <manifest.json> <mirror-id> --reason <reason>`);
}

function readPolicy(args: string[]): 'any' | 'operational' {
  const policy = readFlag(args, '--policy') ?? 'any';
  if (policy !== 'any' && policy !== 'operational') {
    throw new Error('Unsupported --policy. Use any or operational.');
  }
  return policy;
}

function readNow(args: string[]): Date {
  const value = readFlag(args, '--now');
  if (!value) {
    return new Date();
  }
  const now = new Date(value);
  if (Number.isNaN(now.getTime())) {
    throw new Error('Unsupported --now. Use an ISO 8601 timestamp.');
  }
  return now;
}

function initKey(args: string[]) {
  const outputDir = requireFlag(args, '--out');
  fs.mkdirSync(outputDir, { recursive: true });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(
    path.join(outputDir, 'root.public.pem'),
    publicKey.export({ format: 'pem', type: 'spki' }),
  );
  fs.writeFileSync(
    path.join(outputDir, 'root.private.pem'),
    privateKey.export({ format: 'pem', type: 'pkcs8' }),
  );
}

function initManifest(args: string[]) {
  const publisher = requireFlag(args, '--publisher');
  const origin = requireFlag(args, '--origin');
  const now = new Date();
  const expires = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  const manifest: UnsignedManifest = {
    spec_version: '1.0',
    publisher: {
      name: publisher,
      canonical_origin: origin,
    },
    issued_at: now.toISOString(),
    expires_at: expires.toISOString(),
    sequence: 1,
    mirrors: [],
    revoked_mirrors: [],
    keys: [],
    signatures: [],
  };
  process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
}

function main() {
  const [command, ...args] = process.argv.slice(2);

  if (!command) {
    usage();
    process.exit(1);
  }

  if (command === 'init-key') {
    initKey(args);
    return;
  }

  if (command === 'init-manifest') {
    initManifest(args);
    return;
  }

  if (command === 'add-key') {
    const manifestPath = args[0];
    if (!manifestPath) throw new Error('Missing manifest path');
    const key: ManifestKey = {
      id: requireFlag(args, '--id'),
      role: requireFlag(args, '--role') as ManifestKey['role'],
      algorithm: 'ed25519',
      public_key_pem: fs.readFileSync(requireFlag(args, '--public-key'), 'utf8'),
    };
    process.stdout.write(
      `${JSON.stringify(addKey(readJson<MirrorManifest>(manifestPath), key), null, 2)}\n`,
    );
    return;
  }

  if (command === 'add-mirror') {
    const manifestPath = args[0];
    if (!manifestPath) throw new Error('Missing manifest path');
    const mirror: MirrorEntry = {
      id: requireFlag(args, '--id'),
      url: requireFlag(args, '--url'),
      type: (readFlag(args, '--type') ?? 'https') as MirrorEntry['type'],
      status: 'active',
      priority: Number(readFlag(args, '--priority') ?? '10'),
    };
    process.stdout.write(
      `${JSON.stringify(addMirror(readJson<MirrorManifest>(manifestPath), mirror), null, 2)}\n`,
    );
    return;
  }

  if (command === 'sign') {
    const manifestPath = args[0];
    if (!manifestPath) throw new Error('Missing manifest path');
    const privateKeyPem = fs.readFileSync(requireFlag(args, '--private-key'), 'utf8');
    const keyId = requireFlag(args, '--key-id');
    const manifest = readJson<UnsignedManifest>(manifestPath);
    const validationErrors = validateManifestBasics({
      ...manifest,
      signatures: manifest.signatures ?? [],
    });
    if (validationErrors.length > 0) {
      throw new Error(`Manifest validation failed: ${validationErrors.join('; ')}`);
    }
    process.stdout.write(
      `${JSON.stringify(signManifest(manifest, privateKeyPem, keyId, { append: args.includes('--append') }), null, 2)}\n`,
    );
    return;
  }

  if (command === 'payload') {
    const manifestPath = args[0];
    if (!manifestPath) throw new Error('Missing manifest path');
    const manifest = readJson<MirrorManifest | UnsignedManifest>(manifestPath);
    process.stdout.write(
      `${JSON.stringify(
        {
          canonical_payload: unsignedPayload(manifest),
          sha256: payloadSha256(manifest),
        },
        null,
        2,
      )}\n`,
    );
    return;
  }

  if (command === 'verify') {
    const manifestPath = args[0];
    if (!manifestPath) throw new Error('Missing manifest path');
    const policy = readPolicy(args);
    const result = verifyManifest(readJson<MirrorManifest>(manifestPath), readNow(args), { policy });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exit(result.ok ? 0 : 2);
  }

  if (command === 'inspect') {
    const manifestPath = args[0];
    const url = args[1];
    if (!manifestPath || !url) throw new Error('Missing manifest path or URL');
    const manifest = readJson<MirrorManifest>(manifestPath);
    const policy = readPolicy(args);
    const now = readNow(args);
    const verification = verifyManifest(manifest, now, { policy });
    process.stdout.write(
      `${JSON.stringify({ policy, verification, mirror: inspectMirror(manifest, url, now) }, null, 2)}\n`,
    );
    return;
  }

  if (command === 'publish-checklist') {
    const manifestPath = args[0];
    if (!manifestPath) throw new Error('Missing manifest path');
    const manifest = readJson<MirrorManifest>(manifestPath);
    const policy = readPolicy(args);
    const checklist = buildPublishChecklist(manifest, readNow(args), { policy });
    const format = readFlag(args, '--format') ?? 'json';

    if (format === 'json') {
      process.stdout.write(`${JSON.stringify(checklist, null, 2)}\n`);
      return;
    }
    if (format === 'markdown') {
      process.stdout.write(renderPublishChecklistMarkdown(checklist));
      return;
    }
    throw new Error('Unsupported --format. Use json or markdown.');
  }

  if (command === 'trust-handoff') {
    const manifestPath = args[0];
    if (!manifestPath) throw new Error('Missing manifest path');
    const manifest = readJson<MirrorManifest>(manifestPath);
    const policy = readPolicy(args);
    const checklist = buildPublishChecklist(manifest, readNow(args), { policy });
    process.stdout.write(renderTrustHandoff(checklist));
    return;
  }

  if (command === 'revoke') {
    const manifestPath = args[0];
    const mirrorId = args[1];
    if (!manifestPath || !mirrorId) throw new Error('Missing manifest path or mirror ID');
    const reason = requireFlag(args, '--reason');
    process.stdout.write(
      `${JSON.stringify(revokeMirror(readJson<MirrorManifest>(manifestPath), mirrorId, reason), null, 2)}\n`,
    );
    return;
  }

  usage();
  process.exit(1);
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
