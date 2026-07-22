import crypto from 'node:crypto';
import type {
  ManifestKey,
  ManifestSignature,
  MirrorEntry,
  MirrorManifest,
  UnsignedManifest,
} from './types.js';

export type VerificationPolicy = 'any' | 'operational';

const operationalKeyRoles = new Set(['root', 'targets', 'emergency']);
const publicTimelineSummaryMaxAgeSeconds = 15 * 60;

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entryValue]) => entryValue !== undefined)
      .sort(([left], [right]) => left.localeCompare(right));

    return `{${entries
      .map(([key, entryValue]) => `${JSON.stringify(key)}:${canonicalJson(entryValue)}`)
      .join(',')}}`;
  }

  return JSON.stringify(value);
}

export function unsignedPayload(manifest: UnsignedManifest | MirrorManifest): string {
  const { signatures: _signatures, ...payload } = manifest;
  return canonicalJson(payload);
}

export function payloadSha256(manifest: UnsignedManifest | MirrorManifest): string {
  return crypto.createHash('sha256').update(unsignedPayload(manifest)).digest('hex');
}

export function signManifest(
  manifest: UnsignedManifest,
  privateKeyPem: string,
  keyId: string,
  options: { append?: boolean } = {},
): MirrorManifest {
  const key = manifest.keys.find((candidate) => candidate.id === keyId);
  if (!key) {
    throw new Error(`key_id ${keyId} is not listed in manifest keys`);
  }
  if (key.algorithm !== 'ed25519') {
    throw new Error(`key_id ${keyId} does not use ed25519`);
  }

  const signature = crypto.sign(null, Buffer.from(unsignedPayload(manifest)), privateKeyPem);
  const manifestSignature: ManifestSignature = {
    key_id: keyId,
    algorithm: 'ed25519',
    signature: signature.toString('base64'),
  };

  return {
    ...manifest,
    signatures: options.append ? [...(manifest.signatures ?? []), manifestSignature] : [manifestSignature],
  };
}

export function validateManifestBasics(manifest: MirrorManifest | UnsignedManifest): string[] {
  const errors: string[] = [];
  const mirrorIds = new Set<string>();
  const keyIds = new Set<string>();

  if (manifest.spec_version !== '1.0') {
    errors.push('unsupported spec_version');
  }

  if (!Number.isInteger(manifest.sequence) || manifest.sequence < 1) {
    errors.push('sequence must be a positive integer');
  }

  if (Number.isNaN(new Date(manifest.issued_at).getTime())) {
    errors.push('issued_at is not a valid date-time');
  }

  if (Number.isNaN(new Date(manifest.expires_at).getTime())) {
    errors.push('expires_at is not a valid date-time');
  }

  for (const mirror of manifest.mirrors) {
    if (mirrorIds.has(mirror.id)) {
      errors.push(`duplicate mirror id ${mirror.id}`);
    }
    mirrorIds.add(mirror.id);
  }

  for (const key of manifest.keys) {
    if (keyIds.has(key.id)) {
      errors.push(`duplicate key id ${key.id}`);
    }
    keyIds.add(key.id);
    if (key.algorithm !== 'ed25519') {
      errors.push(`unsupported key algorithm for ${key.id}`);
    }
  }

  for (const signature of manifest.signatures ?? []) {
    if (!keyIds.has(signature.key_id)) {
      errors.push(`signature references missing key ${signature.key_id}`);
    }
  }

  return errors;
}

export function verifyManifest(manifest: MirrorManifest, now = new Date(), options: {
  policy?: VerificationPolicy;
} = {}): {
  ok: boolean;
  checked: {
    policy: VerificationPolicy;
    now: string;
    payload_sha256: string;
    mirror_count: number;
    revoked_mirror_count: number;
    key_count: number;
    signature_count: number;
    valid_operational_signatures: number;
  };
  verification_safety_boundary: {
    allowed_to_share: string[];
    do_not_share: string[];
    recheck_before_relay: string[];
    non_claims: string[];
  };
  public_timeline_summary: {
    relay_allowed: boolean;
    status: 'verified' | 'not-verified';
    policy: VerificationPolicy;
    checked_at: string;
    relay_expires_at: string;
    max_age_seconds: number;
    payload_sha256: string;
    active_mirror_count: number;
    revoked_mirror_count: number;
    valid_operational_signatures: number;
    required_context: string[];
    do_not_include: string[];
    non_claims: string[];
  };
  errors: string[];
  remediation: string[];
} {
  const errors: string[] = validateManifestBasics(manifest);
  const policy = options.policy ?? 'any';
  let hasValidOperationalSignature = false;
  let validOperationalSignatures = 0;

  if (new Date(manifest.expires_at).getTime() <= now.getTime()) {
    errors.push('manifest expired');
  }

  if (manifest.signatures.length === 0) {
    errors.push('manifest has no signatures');
  }

  for (const signature of manifest.signatures) {
    const key = manifest.keys.find((candidate) => candidate.id === signature.key_id);

    if (!key) {
      errors.push(`missing key for signature ${signature.key_id}`);
      continue;
    }

    const valid = crypto.verify(
      null,
      Buffer.from(unsignedPayload(manifest)),
      key.public_key_pem,
      Buffer.from(signature.signature, 'base64'),
    );

    if (!valid) {
      errors.push(`invalid signature ${signature.key_id}`);
      continue;
    }

    if (operationalKeyRoles.has(key.role)) {
      hasValidOperationalSignature = true;
      validOperationalSignatures += 1;
    }
  }

  if (policy === 'operational' && manifest.signatures.length > 0 && !hasValidOperationalSignature) {
    errors.push('manifest has no valid operational signature');
  }
  const payloadDigest = payloadSha256(manifest);
  const revokedMirrorIds = new Set(manifest.revoked_mirrors.map((mirror) => mirror.id));
  const activeMirrorCount = manifest.mirrors.filter(
    (mirror) => mirror.status === 'active' && !revokedMirrorIds.has(mirror.id),
  ).length;
  const ok = errors.length === 0;

  return {
    ok,
    checked: {
      policy,
      now: now.toISOString(),
      payload_sha256: payloadDigest,
      mirror_count: manifest.mirrors.length,
      revoked_mirror_count: manifest.revoked_mirrors.length,
      key_count: manifest.keys.length,
      signature_count: manifest.signatures.length,
      valid_operational_signatures: validOperationalSignatures,
    },
    verification_safety_boundary: {
      allowed_to_share: [
        'verification ok status',
        'verification policy, checked time, and payload SHA-256',
        'mirror, key, signature, revoked mirror, and valid operational signature counts',
      ],
      do_not_share: [
        'private keys or signing workflow screenshots',
        'origin infrastructure, provider accounts, or operational contacts',
        'unlisted mirror URLs or mirror candidates not present in the signed manifest',
        'claims that mirror content, hosting provider state, or DDoS resilience were verified',
      ],
      recheck_before_relay: [
        'Confirm ok is true before relaying verification status.',
        'Confirm checked.policy matches the intended publication policy.',
        'Confirm checked.payload_sha256 matches the manifest being distributed.',
      ],
      non_claims: [
        'Does not prove mirror content authenticity.',
        'Does not guarantee censorship circumvention.',
        'Does not verify hosting provider state or DDoS mitigation.',
      ],
    },
    public_timeline_summary: {
      relay_allowed: ok,
      status: ok ? 'verified' : 'not-verified',
      policy,
      checked_at: now.toISOString(),
      relay_expires_at: new Date(now.getTime() + publicTimelineSummaryMaxAgeSeconds * 1000).toISOString(),
      max_age_seconds: publicTimelineSummaryMaxAgeSeconds,
      payload_sha256: payloadDigest,
      active_mirror_count: activeMirrorCount,
      revoked_mirror_count: manifest.revoked_mirrors.length,
      valid_operational_signatures: validOperationalSignatures,
      required_context: [
        'Relay with checked_at, policy, payload_sha256, and active_mirror_count.',
        'Treat relay_expires_at as the last time this verification summary can be reused in a public incident timeline.',
        'Use publish-checklist output for actual mirror URLs and announcement wording.',
        'Re-run verify with the intended policy immediately before public timeline use.',
      ],
      do_not_include: [
        'private keys, signing workflow screenshots, or key-management notes',
        'origin infrastructure, provider accounts, DNS targets, or operational contacts',
        'unlisted mirror URLs or mirror candidates not present in the signed manifest',
        'claims that mirror content, provider state, DDoS mitigation, or censorship circumvention were verified',
      ],
      non_claims: [
        'Does not publish or approve mirror URLs by itself.',
        'Does not prove mirror content authenticity.',
        'Does not verify hosting provider state, DDoS mitigation, or censorship circumvention.',
      ],
    },
    errors,
    remediation: remediationForVerificationErrors(errors),
  };
}

export function remediationForVerificationErrors(errors: string[]): string[] {
  const remediations = new Set<string>();

  for (const error of errors) {
    if (error === 'manifest expired') {
      remediations.add('Refresh expires_at, increase sequence, and re-sign before announcing mirrors.');
      continue;
    }
    if (error === 'manifest has no signatures') {
      remediations.add('Sign the manifest with a listed root, targets, or emergency key.');
      continue;
    }
    if (error === 'manifest has no valid operational signature') {
      remediations.add('Add a valid root, targets, or emergency signature, or verify with --policy any only for observer review.');
      continue;
    }
    if (error.startsWith('invalid signature')) {
      remediations.add('Regenerate signatures after confirming the manifest payload and matching public key.');
      continue;
    }
    if (error.startsWith('missing key for signature') || error.startsWith('signature references missing key')) {
      remediations.add('Add the referenced public key to keys or remove the stale signature.');
      continue;
    }
    if (error.startsWith('duplicate mirror id') || error.startsWith('duplicate key id')) {
      remediations.add('Remove duplicate IDs so each mirror and key has a stable unique identifier.');
      continue;
    }
    if (error.includes('date-time')) {
      remediations.add('Use valid ISO 8601 timestamps for issued_at, expires_at, and mirror validity fields.');
      continue;
    }
    if (error === 'unsupported spec_version') {
      remediations.add('Use manifest spec_version 1.0 for this verifier.');
      continue;
    }
    if (error === 'sequence must be a positive integer') {
      remediations.add('Set sequence to a positive integer and increment it for each signed update.');
      continue;
    }

    remediations.add('Review the manifest against the v1 schema and re-run verify before sharing mirror URLs.');
  }

  return [...remediations];
}

export function inspectMirror(manifest: MirrorManifest, url: string, now = new Date()) {
  const revokedIds = new Set(manifest.revoked_mirrors.map((mirror) => mirror.id));
  const mirror = manifest.mirrors.find((entry) => entry.url === url);

  if (!mirror) {
    return { status: 'unknown' as const, message: 'URL is not listed in the manifest.' };
  }

  if (revokedIds.has(mirror.id)) {
    return { status: 'revoked' as const, message: 'Mirror ID has been revoked.' };
  }

  if (mirror.status !== 'active') {
    return { status: 'paused' as const, message: 'Mirror is listed but not active.' };
  }

  if (mirror.valid_until && new Date(mirror.valid_until).getTime() <= now.getTime()) {
    return { status: 'expired' as const, message: 'Mirror entry is expired.' };
  }

  return { status: 'verified' as const, message: 'Mirror is active and listed.' };
}

export function buildPublishChecklist(
  manifest: MirrorManifest,
  now = new Date(),
  options: { policy?: VerificationPolicy } = {},
) {
  const verification = verifyManifest(manifest, now, options);
  const revokedIds = new Set(manifest.revoked_mirrors.map((mirror) => mirror.id));
  const activeMirrors = manifest.mirrors
    .filter((mirror) => {
      if (mirror.status !== 'active' || revokedIds.has(mirror.id)) {
        return false;
      }
      return !mirror.valid_until || new Date(mirror.valid_until).getTime() > now.getTime();
    })
    .sort((left, right) => left.priority - right.priority)
    .map((mirror) => ({
      id: mirror.id,
      url: mirror.url,
      type: mirror.type,
      priority: mirror.priority,
    }));
  const warnings = [
    ...(verification.ok ? [] : ['Do not publish mirror URLs until manifest verification passes.']),
    ...(activeMirrors.length > 0 ? [] : ['No active, non-revoked mirrors are available to announce.']),
  ];

  return {
    publisher: manifest.publisher,
    sequence: manifest.sequence,
    expires_at: manifest.expires_at,
    policy: options.policy ?? 'any',
    can_publish: verification.ok && activeMirrors.length > 0,
    publication_freshness: {
      checked_at: verification.public_timeline_summary.checked_at,
      relay_expires_at: verification.public_timeline_summary.relay_expires_at,
      max_age_seconds: verification.public_timeline_summary.max_age_seconds,
      publish_requires_recheck_after_expiry: true,
      boundary:
        'Re-run publish-checklist after relay_expires_at before announcing or re-sharing mirror URLs.',
    },
    verification,
    active_mirrors: activeMirrors,
    publication_safety_boundary: {
      allowed_to_share: [
        'signed manifest URL',
        'active mirror URLs listed in this checklist',
        'publisher canonical origin',
        'manifest sequence and expiry time',
      ],
      do_not_share: [
        'unlisted mirror URLs',
        'revoked, paused, or expired mirror entries',
        'private keys or signing workflow screenshots',
        'origin infrastructure, provider accounts, or operational contacts',
        'claims that mirror verification proves article content safety or censorship bypass capability',
      ],
      non_claims: [
        'Does not verify article content authenticity.',
        'Does not prove mirror hosting safety.',
        'Does not guarantee censorship circumvention.',
      ],
      recheck_before_sharing: [
        'Re-run verify with the intended policy and current time.',
        'Confirm can_publish is true.',
        'Confirm the mirror URL appears in active_mirrors.',
      ],
    },
    verification_publication_boundary: {
      allowed_to_relay: [
        'verification ok status and selected signature policy',
        'checked.now verification timestamp',
        'checked.payload_sha256 canonical payload digest',
        'active mirror URLs listed in this checklist',
      ],
      do_not_relay: [
        'private keys, seed material, signing terminals, or key-generation screenshots',
        'unlisted mirror URLs, staging URLs, origin infrastructure, provider accounts, or DNS targets',
        'raw manifest edit history, internal operator chat, or private incident notes',
        'claims that payload verification proves mirror hosting safety or article content authenticity',
        'verification screenshots that have not passed visual-leak-checker review',
      ],
      required_context: [
        'State the publisher canonical origin with relayed verification facts.',
        'State the manifest sequence and expiry time.',
        'State the signature policy used for the check.',
        'State that readers should trust only active_mirrors from this checklist.',
      ],
      non_claims: [
        'Does not prove mirror hosting provider safety.',
        'Does not prove article content authenticity.',
        'Does not guarantee censorship circumvention or DDoS mitigation.',
      ],
    },
    announcement_channel_boundary: {
      allowed_channels: [
        'publisher-controlled canonical website or status page',
        'publisher-controlled social or newsletter account already known to readers',
        'partner or support channel that can also share the signed manifest URL',
      ],
      do_not_use_channels: [
        'newly created anonymous accounts',
        'unmoderated repost chains that strip the signed manifest URL',
        'screenshots of mirror URLs or verification output that have not passed visual-leak-checker review',
        'private operator chats, provider tickets, or DNS dashboards',
      ],
      required_before_channel_post: [
        'Include the signed manifest URL in the same post or directly adjacent context.',
        'Include the publisher canonical origin and manifest sequence.',
        'Confirm publication_freshness.relay_expires_at has not passed.',
        'Confirm every posted mirror URL appears in active_mirrors.',
      ],
      non_claims: [
        'Does not prove the announcement account has not been compromised.',
        'Does not prevent reposts from altering or omitting context.',
        'Does not guarantee censorship circumvention or DDoS mitigation.',
      ],
    },
    announcement_checklist: [
      'Publish the signed manifest URL before or alongside mirror URLs.',
      'Announce only active mirror URLs listed in this checklist.',
      'Include the canonical origin so readers can compare publisher identity.',
      'Avoid posting revoked, paused, expired, or unlisted mirror URLs.',
      'Refresh and re-sign the manifest before the expiry time.',
    ],
    warnings,
  };
}

export function renderPublishChecklistMarkdown(checklist: ReturnType<typeof buildPublishChecklist>): string {
  const lines = [
    `# Signed Mirror Publish Checklist: ${checklist.publisher.name}`,
    '',
    `- Canonical origin: ${checklist.publisher.canonical_origin}`,
    `- Manifest sequence: ${checklist.sequence}`,
    `- Expires at: ${checklist.expires_at}`,
    `- Signature policy: ${checklist.policy}`,
    `- Can publish: ${checklist.can_publish ? 'yes' : 'no'}`,
    `- Checked at: ${checklist.publication_freshness.checked_at}`,
    `- Relay expires at: ${checklist.publication_freshness.relay_expires_at}`,
    `- Max age seconds: ${checklist.publication_freshness.max_age_seconds}`,
    `- Recheck after relay expiry: ${checklist.publication_freshness.publish_requires_recheck_after_expiry ? 'yes' : 'no'}`,
    '',
    '## Active Mirrors',
    '',
    ...(checklist.active_mirrors.length
      ? checklist.active_mirrors.map(
          (mirror) => `- ${mirror.url} (${mirror.type}, priority ${mirror.priority})`,
        )
      : ['- None']),
    '',
    '## Publication Safety Boundary',
    '',
    'Allowed to share:',
    '',
    ...checklist.publication_safety_boundary.allowed_to_share.map((item) => `- ${item}`),
    '',
    'Do not share:',
    '',
    ...checklist.publication_safety_boundary.do_not_share.map((item) => `- ${item}`),
    '',
    'Non-claims:',
    '',
    ...checklist.publication_safety_boundary.non_claims.map((item) => `- ${item}`),
    '',
    '## Announcement Checklist',
    '',
    ...checklist.announcement_checklist.map((item) => `- ${item}`),
    '',
    '## Verification Publication Boundary',
    '',
    'Allowed to relay:',
    '',
    ...checklist.verification_publication_boundary.allowed_to_relay.map((item) => `- ${item}`),
    '',
    'Do not relay:',
    '',
    ...checklist.verification_publication_boundary.do_not_relay.map((item) => `- ${item}`),
    '',
    'Required context:',
    '',
    ...checklist.verification_publication_boundary.required_context.map((item) => `- ${item}`),
    '',
    '## Announcement Channel Boundary',
    '',
    'Allowed channels:',
    '',
    ...checklist.announcement_channel_boundary.allowed_channels.map((item) => `- ${item}`),
    '',
    'Do not use channels:',
    '',
    ...checklist.announcement_channel_boundary.do_not_use_channels.map((item) => `- ${item}`),
    '',
    'Required before channel post:',
    '',
    ...checklist.announcement_channel_boundary.required_before_channel_post.map((item) => `- ${item}`),
    '',
    'Non-claims:',
    '',
    ...checklist.announcement_channel_boundary.non_claims.map((item) => `- ${item}`),
    '',
    '## Warnings',
    '',
    ...(checklist.warnings.length ? checklist.warnings.map((warning) => `- ${warning}`) : ['- None']),
    '',
    '## Remediation',
    '',
    ...(checklist.verification.remediation.length
      ? checklist.verification.remediation.map((item) => `- ${item}`)
      : ['- None']),
    '',
  ];

  return lines.join('\n');
}

export function renderTrustHandoff(checklist: ReturnType<typeof buildPublishChecklist>): string {
  const lines = [
    `# Signed Mirror Trust Handoff: ${checklist.publisher.name}`,
    '',
    '## Trust Decision',
    '',
    `- Can publish: ${checklist.can_publish ? 'yes' : 'no'}`,
    `- Canonical origin: ${checklist.publisher.canonical_origin}`,
    `- Manifest sequence: ${checklist.sequence}`,
    `- Expires at: ${checklist.expires_at}`,
    `- Signature policy: ${checklist.policy}`,
    `- Verification: ${checklist.verification.ok ? 'passed' : 'failed'}`,
    `- Relay expires at: ${checklist.publication_freshness.relay_expires_at}`,
    `- Recheck after relay expiry: ${checklist.publication_freshness.publish_requires_recheck_after_expiry ? 'yes' : 'no'}`,
    '',
    '## Shareable Mirrors',
    '',
    ...(checklist.active_mirrors.length
      ? checklist.active_mirrors.map(
          (mirror) => `- ${mirror.url} (${mirror.type}, priority ${mirror.priority})`,
        )
      : ['- None approved for sharing']),
    '',
    '## Explain This To Readers',
    '',
    checklist.can_publish
      ? 'This mirror list is signed by an accepted key, has not expired, and contains active non-revoked mirror URLs for the publisher above.'
      : 'Do not share mirror URLs from this manifest yet. Verification, expiry, revocation, or active-mirror checks did not pass.',
    '',
    '## Do Not Share',
    '',
    '- Unlisted mirror URLs',
    '- Revoked, paused, or expired mirror entries',
    '- Screenshots of private key material or signing workflows',
    '- Claims that this verifies article content or bypass capability',
    '- Origin infrastructure, provider accounts, or operational contacts',
    '',
    '## Recheck Before Sharing',
    '',
    ...checklist.publication_safety_boundary.recheck_before_sharing.map((item) => `- [ ] ${item}`),
    `- [ ] ${checklist.publication_freshness.boundary}`,
    '',
    '## Verification Publication Boundary',
    '',
    ...checklist.verification_publication_boundary.allowed_to_relay.map((item) => `- Allowed: ${item}`),
    ...checklist.verification_publication_boundary.do_not_relay.map((item) => `- Do not relay: ${item}`),
    ...checklist.verification_publication_boundary.required_context.map((item) => `- Context: ${item}`),
    '',
    '## Announcement Channel Boundary',
    '',
    ...checklist.announcement_channel_boundary.allowed_channels.map((item) => `- Allowed channel: ${item}`),
    ...checklist.announcement_channel_boundary.do_not_use_channels.map((item) => `- Do not use channel: ${item}`),
    ...checklist.announcement_channel_boundary.required_before_channel_post.map((item) => `- Before channel post: ${item}`),
    '',
    '## Operator Checks',
    '',
    ...checklist.announcement_checklist.map((item) => `- [ ] ${item}`),
    '',
    '## Warnings',
    '',
    ...(checklist.warnings.length ? checklist.warnings.map((warning) => `- ${warning}`) : ['- None']),
    '',
    '## Remediation',
    '',
    ...(checklist.verification.remediation.length
      ? checklist.verification.remediation.map((item) => `- ${item}`)
      : ['- None']),
    '',
  ];

  return lines.join('\n');
}

export function addMirror(
  manifest: MirrorManifest | UnsignedManifest,
  mirror: MirrorEntry,
): UnsignedManifest {
  if (manifest.mirrors.some((entry) => entry.id === mirror.id)) {
    throw new Error(`mirror id already exists: ${mirror.id}`);
  }
  if (manifest.mirrors.some((entry) => entry.url === mirror.url)) {
    throw new Error(`mirror url already exists: ${mirror.url}`);
  }

  return {
    ...manifest,
    mirrors: [...manifest.mirrors, mirror],
    sequence: manifest.sequence + 1,
    signatures: [],
  };
}

export function addKey(
  manifest: MirrorManifest | UnsignedManifest,
  key: ManifestKey,
): UnsignedManifest {
  const roles = new Set(['root', 'targets', 'emergency', 'observer']);

  if (manifest.keys.some((entry) => entry.id === key.id)) {
    throw new Error(`key id already exists: ${key.id}`);
  }
  if (!roles.has(key.role)) {
    throw new Error(`unsupported key role: ${key.role}`);
  }
  if (key.algorithm !== 'ed25519') {
    throw new Error(`unsupported key algorithm: ${key.algorithm}`);
  }

  return {
    ...manifest,
    keys: [...manifest.keys, key],
    sequence: manifest.sequence + 1,
    signatures: [],
  };
}

export function revokeMirror(
  manifest: MirrorManifest,
  mirrorId: string,
  reason: string,
  revokedAt = new Date(),
): UnsignedManifest {
  return {
    ...manifest,
    revoked_mirrors: [
      ...manifest.revoked_mirrors,
      {
        id: mirrorId,
        reason,
        revoked_at: revokedAt.toISOString(),
      },
    ],
    signatures: [],
  };
}
