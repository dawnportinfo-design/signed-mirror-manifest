import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  addKey,
  canonicalJson,
  addMirror,
  buildPublishChecklist,
  inspectMirror,
  payloadSha256,
  renderPublishChecklistMarkdown,
  renderTrustHandoff,
  signManifest,
  unsignedPayload,
  validateManifestBasics,
  verifyManifest,
} from './manifest.js';
import type { MirrorManifest, UnsignedManifest } from './types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function fixture(): { manifest: UnsignedManifest; privateKeyPem: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    manifest: {
      spec_version: '1.0',
      publisher: {
        name: 'Example Independent Media',
        canonical_origin: 'https://example.org',
      },
      issued_at: '2026-07-05T00:00:00Z',
      expires_at: '2030-07-05T00:00:00Z',
      sequence: 1,
      mirrors: [
        {
          id: 'mirror-001',
          url: 'https://example-news.pages.dev',
          type: 'https',
          status: 'active',
          priority: 10,
        },
      ],
      revoked_mirrors: [],
      keys: [
        {
          id: 'root-2026',
          role: 'root',
          algorithm: 'ed25519',
          public_key_pem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
        },
      ],
      signatures: [],
    },
  };
}

describe('signed mirror manifest', () => {
  it('canonicalizes object keys before signing', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it('signs and verifies a manifest', () => {
    const { manifest, privateKeyPem } = fixture();
    const signed = signManifest(manifest, privateKeyPem, 'root-2026');

    expect(verifyManifest(signed).ok).toBe(true);
  });

  it('refuses to sign with a key that is not listed in the manifest', () => {
    const { manifest, privateKeyPem } = fixture();

    expect(() => signManifest(manifest, privateKeyPem, 'missing-key')).toThrow('not listed');
  });

  it('detects a tampered manifest', () => {
    const { manifest, privateKeyPem } = fixture();
    const signed = signManifest(manifest, privateKeyPem, 'root-2026');
    signed.mirrors[0]!.url = 'https://evil.example';

    expect(verifyManifest(signed).ok).toBe(false);
  });

  it('reports duplicate mirror IDs before verification', () => {
    const { manifest } = fixture();
    manifest.mirrors.push({ ...manifest.mirrors[0]! });

    expect(validateManifestBasics(manifest)).toContain('duplicate mirror id mirror-001');
  });

  it('detects an expired manifest', () => {
    const { manifest, privateKeyPem } = fixture();
    manifest.expires_at = '2020-01-01T00:00:00Z';
    const signed = signManifest(manifest, privateKeyPem, 'root-2026');
    const result = verifyManifest(signed, new Date('2026-07-05T00:00:00Z'));

    expect(result.errors).toContain('manifest expired');
    expect(result.remediation).toContain(
      'Refresh expires_at, increase sequence, and re-sign before announcing mirrors.',
    );
  });

  it('requires an operational signer when policy is operational', () => {
    const { manifest, privateKeyPem } = fixture();
    manifest.keys[0] = { ...manifest.keys[0]!, role: 'observer' };
    const signed = signManifest(manifest, privateKeyPem, 'root-2026');

    expect(verifyManifest(signed).ok).toBe(true);
    const result = verifyManifest(signed, new Date(), { policy: 'operational' });

    expect(result.errors).toContain('manifest has no valid operational signature');
    expect(result.remediation).toContain(
      'Add a valid root, targets, or emergency signature, or verify with --policy any only for observer review.',
    );
  });

  it('accepts targets and emergency signatures for operational policy', () => {
    const { manifest, privateKeyPem } = fixture();
    manifest.keys[0] = { ...manifest.keys[0]!, role: 'targets' };
    const signed = signManifest(manifest, privateKeyPem, 'root-2026');

    expect(verifyManifest(signed, new Date(), { policy: 'operational' }).ok).toBe(true);
  });

  it('inspects listed and unknown mirrors', () => {
    const { manifest, privateKeyPem } = fixture();
    const signed = signManifest(manifest, privateKeyPem, 'root-2026');

    expect(inspectMirror(signed, 'https://example-news.pages.dev').status).toBe('verified');
    expect(inspectMirror(signed, 'https://unknown.example').status).toBe('unknown');
  });

  it('inspects revoked mirrors', () => {
    const { manifest, privateKeyPem } = fixture();
    manifest.revoked_mirrors.push({
      id: 'mirror-001',
      reason: 'hosting compromised',
      revoked_at: '2026-07-05T00:00:00Z',
    });
    const signed = signManifest(manifest, privateKeyPem, 'root-2026');

    expect(inspectMirror(signed, 'https://example-news.pages.dev').status).toBe('revoked');
  });

  it('builds publish checklists with only active non-revoked mirrors', () => {
    const { manifest, privateKeyPem } = fixture();
    manifest.mirrors.push({
      id: 'mirror-paused',
      url: 'https://paused.example',
      type: 'https',
      status: 'paused',
      priority: 5,
    });
    manifest.mirrors.push({
      id: 'mirror-expired',
      url: 'https://expired.example',
      type: 'https',
      status: 'active',
      priority: 1,
      valid_until: '2026-01-01T00:00:00Z',
    });
    const signed = signManifest(manifest, privateKeyPem, 'root-2026');
    const checklist = buildPublishChecklist(signed, new Date('2026-07-05T00:00:00Z'), {
      policy: 'operational',
    });

    expect(checklist.can_publish).toBe(true);
    expect(checklist.publication_freshness).toMatchObject({
      checked_at: '2026-07-05T00:00:00.000Z',
      relay_expires_at: '2026-07-05T00:15:00.000Z',
      max_age_seconds: 900,
      publish_requires_recheck_after_expiry: true,
    });
    expect(checklist.publication_freshness.boundary).toContain('Re-run publish-checklist after relay_expires_at');
    expect(checklist.active_mirrors).toEqual([
      {
        id: 'mirror-001',
        url: 'https://example-news.pages.dev',
        type: 'https',
        priority: 10,
      },
    ]);
    expect(checklist.announcement_checklist.join('\n')).toContain('signed manifest URL');
    expect(checklist.publication_safety_boundary.allowed_to_share).toContain(
      'active mirror URLs listed in this checklist',
    );
    expect(checklist.publication_safety_boundary.do_not_share).toContain(
      'origin infrastructure, provider accounts, or operational contacts',
    );
    expect(checklist.publication_safety_boundary.non_claims).toContain(
      'Does not guarantee censorship circumvention.',
    );
    expect(checklist.publication_safety_boundary.recheck_before_sharing).toContain(
      'Confirm can_publish is true.',
    );
    expect(checklist.verification_publication_boundary.allowed_to_relay).toContain(
      'checked.payload_sha256 canonical payload digest',
    );
    expect(checklist.verification_publication_boundary.do_not_relay).toContain(
      'unlisted mirror URLs, staging URLs, origin infrastructure, provider accounts, or DNS targets',
    );
    expect(checklist.verification_publication_boundary.required_context).toContain(
      'State the signature policy used for the check.',
    );
    expect(checklist.verification_publication_boundary.non_claims).toContain(
      'Does not guarantee censorship circumvention or DDoS mitigation.',
    );
    expect(checklist.announcement_channel_boundary.allowed_channels).toContain(
      'publisher-controlled canonical website or status page',
    );
    expect(checklist.announcement_channel_boundary.do_not_use_channels).toContain(
      'screenshots of mirror URLs or verification output that have not passed visual-leak-checker review',
    );
    expect(checklist.announcement_channel_boundary.required_before_channel_post).toContain(
      'Confirm publication_freshness.relay_expires_at has not passed.',
    );
    expect(checklist.announcement_channel_boundary.non_claims).toContain(
      'Does not prevent reposts from altering or omitting context.',
    );
  });

  it('renders publish checklists as operator-facing markdown', () => {
    const { manifest, privateKeyPem } = fixture();
    const signed = signManifest(manifest, privateKeyPem, 'root-2026');
    const markdown = renderPublishChecklistMarkdown(
      buildPublishChecklist(signed, new Date('2026-07-05T00:00:00Z')),
    );

    expect(markdown).toContain('# Signed Mirror Publish Checklist');
    expect(markdown).toContain('- Relay expires at: 2026-07-05T00:15:00.000Z');
    expect(markdown).toContain('- Recheck after relay expiry: yes');
    expect(markdown).toContain('## Active Mirrors');
    expect(markdown).toContain('https://example-news.pages.dev');
    expect(markdown).toContain('## Publication Safety Boundary');
    expect(markdown).toContain('## Verification Publication Boundary');
    expect(markdown).toContain('checked.payload_sha256 canonical payload digest');
    expect(markdown).toContain('## Announcement Channel Boundary');
    expect(markdown).toContain('publisher-controlled canonical website or status page');
    expect(markdown).toContain('Confirm publication_freshness.relay_expires_at has not passed.');
    expect(markdown).toContain('Does not guarantee censorship circumvention.');
    expect(markdown).toContain('## Announcement Checklist');
    expect(markdown).toContain('## Remediation');
    expect(markdown).toContain('- None');
  });

  it('renders trust handoffs for reader-facing mirror decisions', () => {
    const { manifest, privateKeyPem } = fixture();
    const signed = signManifest(manifest, privateKeyPem, 'root-2026');
    const handoff = renderTrustHandoff(
      buildPublishChecklist(signed, new Date('2026-07-05T00:00:00Z'), {
        policy: 'operational',
      }),
    );

    expect(handoff).toContain('# Signed Mirror Trust Handoff');
    expect(handoff).toContain('## Trust Decision');
    expect(handoff).toContain('- Can publish: yes');
    expect(handoff).toContain('- Relay expires at: 2026-07-05T00:15:00.000Z');
    expect(handoff).toContain('- Recheck after relay expiry: yes');
    expect(handoff).toContain('## Explain This To Readers');
    expect(handoff).toContain('active non-revoked mirror URLs');
    expect(handoff).toContain('## Do Not Share');
    expect(handoff).toContain('Unlisted mirror URLs');
    expect(handoff).toContain('## Recheck Before Sharing');
    expect(handoff).toContain('## Verification Publication Boundary');
    expect(handoff).toContain('Do not relay: unlisted mirror URLs');
    expect(handoff).toContain('## Announcement Channel Boundary');
    expect(handoff).toContain('Allowed channel: publisher-controlled canonical website or status page');
    expect(handoff).toContain('Before channel post: Confirm publication_freshness.relay_expires_at has not passed.');
    expect(handoff).toContain('Confirm can_publish is true.');
    expect(handoff).toContain('Re-run publish-checklist after relay_expires_at');
    expect(handoff).toContain('## Remediation');
  });

  it('renders remediation guidance when publication must stop', () => {
    const { manifest, privateKeyPem } = fixture();
    manifest.expires_at = '2020-01-01T00:00:00Z';
    const signed = signManifest(manifest, privateKeyPem, 'root-2026');
    const checklist = buildPublishChecklist(signed, new Date('2026-07-05T00:00:00Z'), {
      policy: 'operational',
    });
    const markdown = renderPublishChecklistMarkdown(checklist);
    const handoff = renderTrustHandoff(checklist);

    expect(checklist.can_publish).toBe(false);
    expect(checklist.verification.remediation).toContain(
      'Refresh expires_at, increase sequence, and re-sign before announcing mirrors.',
    );
    expect(markdown).toContain('## Remediation');
    expect(markdown).toContain('Refresh expires_at, increase sequence, and re-sign before announcing mirrors.');
    expect(handoff).toContain('Do not share mirror URLs from this manifest yet.');
    expect(handoff).toContain('Refresh expires_at, increase sequence, and re-sign before announcing mirrors.');
  });

  it('adds a mirror and clears signatures for re-signing', () => {
    const { manifest, privateKeyPem } = fixture();
    const signed = signManifest(manifest, privateKeyPem, 'root-2026');
    const updated = addMirror(signed, {
      id: 'mirror-002',
      url: 'https://second.example',
      type: 'https',
      status: 'active',
      priority: 20,
    });

    expect(updated.sequence).toBe(2);
    expect(updated.signatures).toEqual([]);
    expect(updated.mirrors).toHaveLength(2);
  });

  it('refuses duplicate mirror URLs', () => {
    const { manifest } = fixture();

    expect(() =>
      addMirror(manifest, {
        id: 'mirror-002',
        url: 'https://example-news.pages.dev',
        type: 'https',
        status: 'active',
        priority: 20,
      }),
    ).toThrow('mirror url already exists');
  });

  it('adds a key and clears signatures for re-signing', () => {
    const { manifest, privateKeyPem } = fixture();
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const signed = signManifest(manifest, privateKeyPem, 'root-2026');

    const updated = addKey(signed, {
      id: 'emergency-2026',
      role: 'emergency',
      algorithm: 'ed25519',
      public_key_pem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    });

    expect(updated.sequence).toBe(2);
    expect(updated.signatures).toEqual([]);
    expect(updated.keys.map((key) => key.id)).toContain('emergency-2026');
  });

  it('refuses duplicate key IDs', () => {
    const { manifest } = fixture();

    expect(() =>
      addKey(manifest, {
        id: 'root-2026',
        role: 'targets',
        algorithm: 'ed25519',
        public_key_pem: manifest.keys[0]!.public_key_pem,
      }),
    ).toThrow('key id already exists');
  });

  it('matches the published manifest v1 Ed25519 test vector', () => {
    const vector = JSON.parse(
      fs.readFileSync(
        path.join(__dirname, '..', 'test-vectors', 'manifest-v1-ed25519.json'),
        'utf8',
      ),
    ) as { canonical_payload: string; signed_manifest: MirrorManifest };

    expect(unsignedPayload(vector.signed_manifest)).toBe(vector.canonical_payload);
    expect(payloadSha256(vector.signed_manifest)).toBe(
      'c7d5e19db766cfce89ca340facef733e63604ad42a9bb0a7c219a5f63fc2020d',
    );
    expect(
      verifyManifest(vector.signed_manifest, new Date('2026-07-08T00:00:00.000Z')),
    ).toEqual({
      ok: true,
      checked: {
        policy: 'any',
        now: '2026-07-08T00:00:00.000Z',
        payload_sha256: 'c7d5e19db766cfce89ca340facef733e63604ad42a9bb0a7c219a5f63fc2020d',
        mirror_count: 1,
        revoked_mirror_count: 0,
        key_count: 1,
        signature_count: 1,
        valid_operational_signatures: 1,
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
        relay_allowed: true,
        status: 'verified',
        policy: 'any',
        checked_at: '2026-07-08T00:00:00.000Z',
        relay_expires_at: '2026-07-08T00:15:00.000Z',
        max_age_seconds: 900,
        payload_sha256: 'c7d5e19db766cfce89ca340facef733e63604ad42a9bb0a7c219a5f63fc2020d',
        active_mirror_count: 1,
        revoked_mirror_count: 0,
        valid_operational_signatures: 1,
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
      errors: [],
      remediation: [],
    });
  });
});
