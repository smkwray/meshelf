# Work Order 03 — secure direct network and Tailscale integration

## Ownership

`crates/meshelf-protocol/**`, `crates/meshelf-net/**`, `crates/meshelf-tailscale/**`.

## Objective

Complete authenticated peer discovery, private binding, one-shot transfer, timeouts, reconnect behavior, and exact receipt semantics.

## Required properties

- bind only discovered Tailscale IPs;
- fail closed if no private Tailscale address exists;
- no wildcard/LAN fallback;
- on-demand probe only, no heartbeat;
- source identity must match hello, signature, trusted key, and Tailscale remote identity;
- one push per connection;
- bounded frame and stage timeouts;
- sender distinguishes rejected, offline, failed, and uncertain;
- no queue for direct push;
- listener restarts safely when Tailscale addresses change.

## Acceptance

Two real devices exchange synthetic text directly with a third device off. LAN connection fails. Offline target produces immediate refusal and never causes a later write.
