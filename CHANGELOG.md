# Changelog

## v0.1.0 - Public Alpha Candidate

This release prepares Signed Mirror Manifest for specification review, compatibility testing, and grant evaluation. It is not a censorship-circumvention service.

### Added

- Manifest v1 draft and JSON Schema.
- TypeScript CLI for key generation, manifest initialization, key addition, mirror addition, canonical payload inspection, signing, verification, URL inspection, mirror revocation, and publish checklist generation.
- Ed25519 signing and verification.
- Operational signature policy for root, targets, and emergency key roles.
- Machine-readable verify, inspect, and publish-checklist schemas.
- Fixed Ed25519 test vector for independent implementations.
- CI smoke checks for schema validation, tests, build, and CLI behavior.

### Verification

- `npm run ci`
- TypeScript typecheck, example validation, Vitest tests, build, and CLI smoke checks.

### Portfolio Gate

- From the portfolio root, `npm run readiness`, `npm run supply-chain:safety`, `npm run metadata:boundary`, `npm run frontend:capability-map`, `npm run cli:entrypoints`, `npm run number:local-first`, `npm run docs:advisory-safety`, `npm run safety:contracts-inventory`, and `npm run verify` must pass before public release.

### Public Safety Boundaries

- Public release evidence is synthetic-only and not a field-validated deployment claim.
- Do not include real account inventories, phone numbers, private keys, incident logs, screenshots, victim data, live phishing URLs, DNS targets, origin IPs, provider tickets, private user exports, operational infrastructure details, private contacts, active incident details, provider correspondence, legal requests, or time-sensitive safety requests.
- Does not guarantee account recovery, complete anonymization, DDoS mitigation, censorship circumvention, or field deployment.

### Known Limits

- This is not a field-validated deployment.
- Verifies signed mirror lists, not mirror content authenticity.
- Does not host mirrors, bypass firewalls, manage DNS, or protect private keys.
- Public examples and test vectors are synthetic and must not include real private keys or unreleased operational mirror URLs.
