# Security Policy

Signed Mirror Manifest is intended for civil society publishers under censorship pressure.

## Supported Versions

This project is an early public prototype. Security fixes are prepared against the current `main` branch until versioned releases exist.

## Reporting Security Issues

Use GitHub private vulnerability reporting when enabled by the repository owner. If private reporting is not available, do not post exploit details publicly; open a minimal public issue asking for a private contact path.

## Emergency and Real-World Incident Boundary

This prototype is not an emergency response channel. Do not use public issues for active incidents, time-sensitive safety requests, account recovery emergencies, legal requests, provider coordination, or real-world threat reporting. Public reports must use synthetic reproduction steps and should never include sensitive operational details.

Do not file public issues containing:

- Private signing keys.
- Unannounced emergency mirrors.
- Details about a compromised publisher account.
- Sensitive incident timelines.

## Public Reporting Boundary

Do not post real account inventories, phone numbers, private keys, incident logs, screenshots, victim data, live phishing URLs, DNS targets, origin IPs, provider tickets, private user exports, operational infrastructure details, or private contacts in public issues, pull requests, discussions, release notes, or demo artifacts. Use synthetic reproduction steps and ask for a private reporting path when sensitive details are needed.

## Coordinated Disclosure

- Use synthetic manifests and test vectors whenever possible.
- Give maintainers time to triage before public disclosure.
- Do not test against real publisher infrastructure without explicit authorization.
- If the issue could help distribute fake, stale, or revoked mirrors, minimize details until a private channel exists.

## Publication Security Gate

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

## Security Assumptions

The initial CLI is a reference implementation. High-risk deployments should obtain an independent security review before relying on it operationally.
