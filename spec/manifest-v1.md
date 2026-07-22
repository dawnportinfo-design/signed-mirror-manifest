# Manifest v1

`mirror-manifest.json` lists publisher-approved mirrors and cryptographic signatures over the manifest payload.

## Required Fields

- `spec_version`: currently `1.0`.
- `publisher`: publisher name and canonical origin.
- `issued_at`: ISO timestamp.
- `expires_at`: ISO timestamp.
- `sequence`: monotonic integer to reduce rollback risk.
- `mirrors`: active or paused mirrors.
- `revoked_mirrors`: revoked mirror IDs.
- `keys`: public keys allowed to verify signatures.
- `signatures`: signatures over the canonical unsigned payload.

## Signature Scope

Signatures cover the canonical JSON payload with `signatures` removed. Implementations must sort object keys before signing and verifying.

A fixed Ed25519 test vector is available at `test-vectors/manifest-v1-ed25519.json`. Independent implementations should reproduce the `canonical_payload` value exactly and verify the included signature before claiming manifest v1 compatibility.

The reference CLI can print the canonical signing payload and SHA-256 digest:

```bash
smm payload mirror-manifest.json
```

## Key Roles

- `root`: offline trust anchor for publishing or replacing trusted public keys.
- `targets`: routine mirror-list publication.
- `emergency`: rapid incident response key for urgent mirror additions or revocations.
- `observer`: optional cosignature by a supporting organization.

The reference CLI allows any listed Ed25519 key to sign. Production deployments should define which roles are accepted by their verification policy.

The reference CLI supports `verify --policy operational`, which requires at least one valid signature from a `root`, `targets`, or `emergency` key. `observer` signatures remain useful for transparency or support, but do not authorize a mirror list under the operational policy.

## Mirror Status

- `active`: currently approved.
- `paused`: known but not recommended.
- `revoked`: must appear only in `revoked_mirrors`.

## Non-Goals

- Hosting mirrors.
- Authenticating article contents.
- DNSSEC replacement.
- Anonymous access.
