# Contributing

Signed Mirror Manifest is a security-sensitive specification and reference CLI. Contributions should preserve interoperability, avoid leaking operational data, and keep manifest v1 behavior testable.

## Contribution Data Boundary

Use synthetic data, public test vectors, or heavily abstracted examples only. Do not include real account inventories, phone numbers, private keys, incident logs, screenshots, victim data, live phishing URLs, DNS targets, origin IPs, provider tickets, private user exports, operational infrastructure details, private contacts, active incident details, provider correspondence, legal requests, or time-sensitive safety requests in issues, pull requests, tests, fixtures, docs, screenshots, or demos.

If a change requires sensitive reproduction details, stop and ask for a private reporting path instead of opening a public issue or pull request.

## Safe Contributions

- Improve documentation, examples, and threat-model clarity.
- Use synthetic manifests, synthetic incident context, or fixed test vectors for public examples.
- Add tests for signing, verification, canonical payload generation, and policy handling.
- Improve CLI ergonomics without changing manifest semantics.
- Propose schema or spec changes with compatibility notes.
- Add independent implementation notes or test vectors.

## Compatibility Rules

- Changes to canonical JSON, signature scope, key roles, or verification policy must include tests.
- Changes that affect manifest v1 compatibility must update the relevant spec section.
- Test vectors should remain stable unless a deliberate versioned compatibility change is documented.
- Observer signatures must not silently become operational authorization.

## Do Not Submit

- Private signing keys.
- Real emergency mirror lists.
- Unannounced incident URLs.
- Details about compromised publisher infrastructure.
- Changes that promise censorship bypass, hosting safety, or content authenticity beyond the manifest scope.

## Development

```bash
npm install
npm run ci
```

## Portfolio Gate

Before public release or grant-review packaging, run these from the portfolio root:

```bash
npm run readiness
npm run frontend:capability-map
npm run cli:entrypoints
npm run number:local-first
npm run docs:advisory-safety
npm run safety:contracts-inventory
npm run supply-chain:safety
npm run metadata:boundary
npm run verify
```
