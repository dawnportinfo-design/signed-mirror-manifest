# Threat Model

## In Scope

- Fake mirror URLs distributed through social media, email, or chat.
- Stale mirrors that should no longer be trusted.
- Emergency mirrors that need rapid publication.
- Key rotation and revocation.
- Basic rollback resistance through manifest expiry and sequence numbers.
- Key identifiers that do not match the signed manifest.
- Revoked mirrors that continue to circulate after an incident.

## Out of Scope

- Fully compromised publisher signing environment.
- Browser or device malware.
- Hosting provider compromise after a mirror was validly listed.
- Article-level content provenance.
- Network-level censorship bypass.

## Safety Goal

Users and tools should be able to verify that a mirror URL is publisher-listed, signed, unexpired, and not revoked.

## Residual Risk

A valid manifest cannot prove that the mirror host has not been compromised after publication. It only proves that the publisher listed the URL at signing time and has not revoked that mirror in the inspected manifest.
