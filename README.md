# Signed Mirror Manifest

[![CI](https://github.com/dawnportinfo-design/signed-mirror-manifest/actions/workflows/ci.yml/badge.svg)](https://github.com/dawnportinfo-design/signed-mirror-manifest/actions/workflows/ci.yml)

GitHub description: Signed manifest specification and CLI for publishing and verifying trusted mirror URL metadata.

Signed Mirror Manifest is an open specification and CLI for publishing, signing, verifying, rotating, and revoking trusted mirror URL lists during censorship events.

This project does **not** host mirrors, bypass firewalls, or authenticate article content. It solves the narrower trust problem:

> Is this mirror URL listed by the publisher, signed by a trusted key, not expired, and not revoked?

## Public Review Links

- GitHub URL: https://github.com/dawnportinfo-design/signed-mirror-manifest
- Portfolio supplement: `output/pdf/dawnport-otf-application-supplement.pdf` from the portfolio root.
- Publication commands: `docs/github-publication-commands.md` from the portfolio root.

## Review in 3 Minutes

- Value: gives publishers and audiences a signed, verifiable mirror URL list during access disruption.
- Reviewer cue: Review this for the trust model, Ed25519 signing workflow, manifest schema, revocation behavior, and CLI contracts.
- Safety boundary: verifies mirror-list authenticity only; it does not host mirrors, bypass firewalls, or authenticate content.
- Technical check: run `npm run ci` to typecheck, validate examples, run tests, build, and execute CLI smoke checks.
- Portfolio contract: from the portfolio root, run `npm run mirror:smm-contract` and `npm run mirror:compat`.
- Pass condition: example manifests validate, Vitest passes, TypeScript builds, and CLI smoke checks pass.
- Prototype status: prototype-stage, synthetic-only examples, reviewer-ready checks.

## Technical Value, Features, and Differentiation

Signed Mirror Manifest gives publishers a simple way to say, "these mirror URLs are ours, this list is current, and revoked mirrors should no longer be trusted." It separates mirror trust from social-media forwarding, chat screenshots, and stale emergency instructions.

Key functions:

- manifest v1 JSON format for mirror URLs, expiry, sequence numbers, keys, and revocations
- Ed25519 signing and verification workflow
- CLI commands for key generation, signing, verification, inspection, and publication handoff
- rollback protection through sequence and expiry fields
- JSON Schema validation and deterministic test vectors
- safe publication boundaries that avoid exposing private operations, keys, or incident details

What makes it different is that it does not try to be a hosting platform or circumvention tool. It solves the smaller but critical authenticity layer: when a site is blocked or under pressure, supporters need a verifiable list of legitimate mirrors before they amplify links.

Having this tool helps independent media and civil society publishers reduce fake-mirror risk, retire compromised links, and give partners a machine-checkable object instead of informal trust chains.

## Portfolio Verification

This repository is part of the six-tool Dawnport OTF toolkit. From the portfolio root, run
`npm run readiness` before release review, then run `npm run verify` to check this CLI together
with `mirror-readiness-checker` compatibility, JSON-output contracts, and the wider operational
toolchain. Run `npm run contracts:artifact` from the portfolio root to write
`artifacts/contract-summary.json`, the machine-readable cross-tool contract summary used by
portfolio CI.

Also run `npm run frontend:capability-map`, `npm run cli:entrypoints`,
`npm run number:local-first`, `npm run docs:advisory-safety`, and
`npm run safety:contracts-inventory` from the portfolio root before public release or reviewer
handoff.

## Why

During blocking, DDoS, or domain seizure pressure, independent media and civil society sites often distribute mirror URLs through social posts, chat groups, email, GitHub Pages, or partner sites. Users need a lightweight way to distinguish authentic mirrors from fake, stale, or revoked mirrors.

## Current Prototype

Early preparation release:

- Manifest v1 draft.
- JSON Schema.
- TypeScript CLI.
- Ed25519 signing and verification with PEM keys.
- Basic rollback protection through expiry and sequence fields.
- Mirror inspection with verified / unknown / paused / expired / revoked states.
- Publish checklist output for safe mirror announcement handoff.
- Example manifest.
- Ed25519 manifest v1 test vector.
- Example validation in CI.
- Synthetic examples and test vectors only. No real emergency mirror operations, private keys, or incident data are included.

## What This Does Not Do

- does not host mirrors or publish article content
- does not guarantee censorship circumvention
- does not authenticate page content after a mirror URL is opened
- does not include real emergency mirror operations, private keys, or incident data

## CLI

```bash
npm install
npm run build
```

Generate a key pair:

```bash
node dist/cli.js init-key --out examples/keys
```

Create a starter manifest:

```bash
node dist/cli.js init-manifest --publisher "Example Independent Media" --origin https://example.org > mirror-manifest.json
```

Add the public signing key to the manifest:

```bash
node dist/cli.js add-key mirror-manifest.json --id example-root --role root --public-key examples/keys/root.public.pem > unsigned-with-key.json
```

Add a mirror candidate:

```bash
node dist/cli.js add-mirror unsigned-with-key.json --id mirror-001 --url https://example-news.pages.dev > unsigned-with-mirror.json
```

Inspect the canonical signing payload and digest:

```bash
node dist/cli.js payload unsigned-with-mirror.json
```

Sign a manifest:

```bash
node dist/cli.js sign unsigned-with-mirror.json --private-key examples/keys/root.private.pem --key-id example-root > signed-manifest.json
```

Verify:

```bash
node dist/cli.js verify examples/signed-manifest.json
```

The machine-readable `verify` output is described by
[`schemas/verify-result.schema.json`](schemas/verify-result.schema.json).
It includes a `checked` section with the verification policy, verification time, canonical payload
SHA-256, signature count, and valid operational signature count. It also includes
`verification_safety_boundary`, which separates shareable verification facts from private keys,
origin infrastructure, unlisted mirrors, and claims about mirror content, provider safety, DDoS
mitigation, or censorship circumvention. Use these fields when handing results to
`mirror-readiness-checker` or reviewers so they can see exactly what was verified and what must not
be relayed before any mirror URL is announced.
`public_timeline_summary` provides the minimal verified facts that `ddos-first-hour`
`public_timeline_boundary` can relay: verification status, policy, checked time, payload hash,
`relay_expires_at`, active mirror count, revoked mirror count, and operational signature count. It
does not include or approve mirror URLs; use `publish-checklist` for actual public mirror
announcement text and re-run verification after the relay expiry.

Require a valid `root`, `targets`, or `emergency` signature:

```bash
node dist/cli.js verify examples/signed-manifest.json --policy operational
```

Pin the verification time for reproducible audits or test vectors:

```bash
node dist/cli.js verify examples/signed-manifest.json --policy operational --now 2026-07-08T00:00:00.000Z
```

Inspect a URL:

```bash
node dist/cli.js inspect examples/signed-manifest.json https://example-news.pages.dev
```

Inspect a URL under the operational signer policy:

```bash
node dist/cli.js inspect examples/signed-manifest.json https://example-news.pages.dev --policy operational
```

The machine-readable `inspect` output is described by
[`schemas/inspect-result.schema.json`](schemas/inspect-result.schema.json), and CI validates the
CLI smoke output against that schema.

Generate a publication checklist for operators:

```bash
node dist/cli.js publish-checklist examples/signed-manifest.json --policy operational --format markdown
```

The machine-readable `publish-checklist` output is described by
[`schemas/publish-checklist.schema.json`](schemas/publish-checklist.schema.json). It includes
verification status, `publication_freshness`, active non-revoked mirrors, `publication_safety_boundary`,
`verification_publication_boundary`, `announcement_channel_boundary`, announcement checklist items,
and warnings that should block publication. The safety boundaries separate what can
be shared from private keys, origin infrastructure, provider accounts, unlisted URLs, and claims
that mirror verification proves article content safety or censorship bypass capability.
`verification_publication_boundary` limits relayed verification facts to status, policy, checked
time, payload digest, and active checklist mirrors, and blocks unreviewed verification screenshots
or internal operator notes from public trust handoffs.
`announcement_channel_boundary` limits mirror URL posts to publisher-controlled or manifest-capable
channels, blocks newly created anonymous accounts and unreviewed screenshots, and requires the signed
manifest URL, canonical origin, sequence, freshness expiry, and `active_mirrors` check before posting.

Generate a trust handoff for support channels or partner sites:

```bash
node dist/cli.js trust-handoff examples/signed-manifest.json --policy operational
```

The trust handoff explains whether URLs are shareable, which mirrors are approved, what must not be
shared, and how to describe the signed-manifest trust boundary without overclaiming.

Revoke a mirror ID:

```bash
node dist/cli.js revoke examples/signed-manifest.json mirror-001 --reason "hosting compromised" > revoked-manifest.json
```

## Threat Model

See [spec/threat-model.md](spec/threat-model.md).

## Manifest Spec

See [spec/manifest-v1.md](spec/manifest-v1.md).

Operational key and mirror update guidance is in [spec/operational-runbook.md](spec/operational-runbook.md).

## Test Vectors

The repository includes a fixed Ed25519 manifest v1 vector for independent implementations:

- [test-vectors/manifest-v1-ed25519.json](test-vectors/manifest-v1-ed25519.json)

The vector pins the canonical unsigned payload, its SHA-256 digest, and the expected signature over that payload.

## Development

```bash
npm run ci
```

The same command is configured in `.github/workflows/ci.yml` for GitHub Actions.

See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing spec, CLI, or compatibility changes.

## Suggested Operational Model

- Keep the `root` key offline.
- Use a `targets` or `emergency` key for day-to-day mirror list updates.
- Use `verify --policy operational` when observer-only signatures should not authorize a mirror list.
- Use `publish-checklist --policy operational` before announcing mirror URLs.
- Check `publication_freshness.relay_expires_at` and re-run `publish-checklist` after expiry before re-sharing URLs.
- Check `publication_safety_boundary` before copying URLs into public posts or partner handoffs.
- Check `verification_publication_boundary` before relaying verification facts or screenshots.
- Keep manifest expirations short enough to limit stale mirrors.
- Increase `sequence` when publishing a new manifest.
- Publish the same signed manifest through multiple channels.
- Use `trust-handoff --policy operational` when a partner or support channel needs a concise
  explanation of why specific mirror URLs are safe to share.

## License

MIT
