# Work Order 02 — signed identity, pairing, and revocation

## Ownership

New identity modules assigned by the integrator; coordinate any core/protocol API changes by handoff. Do not edit UI layout except narrowly exposed callbacks agreed with the UI lane.

## Objective

Implement per-installation Ed25519 identity, protected private-key storage, canonical signing, explicit pairing, trust binding, and revocation.

## Required properties

- no shared global mesh password;
- no trust-on-first-use without explicit approval;
- human-verifiable short authentication string;
- message signature covers source, target, ID, deadline, mode, and payload digest;
- key substitution and signature tampering rejected;
- trusted peer binds public key and Tailscale identity/address evidence;
- revocation immediate and durable;
- key material never logged;
- deny-all remains the default before pairing.

## Acceptance

Two local test peers pair explicitly and exchange a signed synthetic message. Every mutation test fails before body persistence. A revoked peer is refused.
