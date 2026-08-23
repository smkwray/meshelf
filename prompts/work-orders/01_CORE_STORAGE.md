# Work Order 01 — core and durable receive ledger

## Ownership

`crates/meshelf-core/**`, `crates/meshelf-store/**` only.

## Objective

Compile, test, and harden the seeded at-most-once receive state machine and redb persistence without changing product semantics.

## Required cases

- valid first delivery;
- exact duplicate after applied;
- ID reused with different envelope;
- clipboard failure;
- crash/leftover `Applying` state;
- resume from `Recorded`;
- storage failure before side effect;
- storage failure after side effect returns uncertain;
- concurrent duplicate claims;
- 1 MiB exact boundary and oversize refusal.

## Acceptance

No path can apply the same message automatically twice. No success is returned before the durable state and clipboard side effect meet the documented boundary. Tests survive process restart against a real redb file.
