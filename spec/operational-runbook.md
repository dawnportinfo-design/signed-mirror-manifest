# Operational Runbook

This runbook describes a conservative workflow for using Signed Mirror Manifest during censorship, DDoS, domain seizure, or access-disruption events.

It is not a substitute for a security review. Use synthetic exercises before relying on it during a real incident.

## Key Roles

Use separate keys for different risk levels:

- `root`: offline trust anchor. Use only to introduce, replace, or retire trusted signing keys.
- `targets`: routine mirror-list updates.
- `emergency`: pre-authorized incident key for urgent mirror additions or revocations.
- `observer`: optional supporting organization cosignature. Observer signatures should not authorize mirror lists under `operational` policy.

Recommended default verifier policy:

```bash
smm verify mirror-manifest.json --policy operational
```

For reproducible exercises, audits, and compatibility tests, pin the verifier clock:

```bash
smm verify mirror-manifest.json --policy operational --now 2026-07-08T00:00:00.000Z
```

## Initial Setup

1. Generate keys on a trusted machine.
2. Store the `root` private key offline.
3. Add public keys to a starter manifest.
4. Add at least one tested mirror URL.
5. Sign the manifest with a `root`, `targets`, or `emergency` key.
6. Publish the same signed manifest through multiple channels.
7. Verify the published copy from a separate environment.

## Routine Mirror Update

1. Add or pause mirror entries.
2. Increase `sequence`.
3. Clear old signatures.
4. Sign the updated manifest.
5. Verify with `--policy operational`.
6. Generate a publish checklist.
7. Publish and archive the signed manifest.

The reference CLI clears signatures when `add-mirror`, `add-key`, or `revoke` changes signed content.

Generate the operator handoff before public announcement:

```bash
smm publish-checklist mirror-manifest.json --policy operational --format markdown
```

Treat `can_publish: false` as a stop condition. Announce only active, non-revoked mirror URLs from
the checklist, and publish the signed manifest URL before or alongside mirror URLs.

## Emergency Mirror Publication

Use the `emergency` key only when the routine update path is blocked or too slow.

1. Add the emergency mirror.
2. Keep `expires_at` short.
3. Sign with the emergency key.
4. Verify with `--policy operational`.
5. Generate a publish checklist and confirm it has no publication-blocking warnings.
6. Publish through channels that users already trust.
7. Replace with a routine `targets` signed manifest when the incident stabilizes.

## Revocation

Revoke a mirror when it is compromised, stale, impersonating content, or no longer controlled by the publisher.

1. Add the mirror ID to `revoked_mirrors`.
2. Increase `sequence`.
3. Re-sign the manifest.
4. Publish the revoked manifest through all available channels.
5. Ask partners and supporters to stop sharing older manifest copies.

## Rollback Resistance

Verifiers should consider:

- `expires_at`: expired manifests should fail verification.
- `sequence`: lower sequence numbers are suspicious when a higher sequence has already been observed.
- `revoked_mirrors`: revoked IDs should remain visible in newer manifests long enough for stale links to be recognized.

The current reference CLI validates expiry and signatures. Long-term clients should store the highest observed sequence per publisher.

## What Not To Publish

Do not publish:

- private signing keys
- unannounced mirror infrastructure details
- origin IPs
- incident timelines that help attackers
- private operational contacts

Use synthetic examples in issues, docs, and exercises.
