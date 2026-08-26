# Agent handoff

- Work order: Step 9 Unit B protocol cutover
- Agent/lane: build lane, BMST/macOS
- Starting commit or source hash: `5a8dc0c3f2c2a3771aa30f993eef3285d08716d0`
- Ending commit or patch identity: uncommitted working-tree patch
- Owned files: protocol, core/store migration, net, control, desktop, CLI, simulator, and related manifest files listed by `git status --short`
- Files intentionally not touched: shared destination kernels in `crates/meshelf-core/src/destination.rs`, `crates/meshelf-net/src/destination.rs`, and `crates/meshelf-platform/src/filesystem.rs`; documents other than current state

## Changes

- Completed the v2 composition and selected it in desktop and headless production entry points.
- Added startup migration before listener binding: count/remove all v1 ledger rows transactionally, preserve published Incoming files, remove app-owned partials and completion markers only, and block on cleanup failure.
- Added bounded hello-only v1 refusal and v2 capability checks for announcement and fetch clients.
- Removed v1 push/file compositions and operational receive-store behavior while retaining the migration table definition and shared destination kernels.

## Defects found

- BMST sandbox denies `sysctl` and loopback socket binds. Those platform/network gates remain unproven and were not weakened.

## Acceptance criteria status

- Source and focused non-loopback tests pass where executable.
- Full workspace and listener tests are blocked by the sandbox restrictions above.
- Windows maximum-length and collision tests remain present in the shared destination module but require a permitted Windows run for platform proof.

## Commands run

```text
source scripts/rust-env.sh
blocked: sysctl -n hw.logicalcpu -> sysctlbyname(hw.logicalcpu) failed: Operation not permitted
```

Pinned Rust 1.92.0 was used for all Cargo commands after that environment helper was blocked.

## Platform and tool versions

- BMST, macOS, Rust host 1.91.1; pinned toolchain Rust 1.92.0.

## New tests

- Production hello/cutover refusal and client capability tests.
- Migration count, preservation, cleanup, idempotence, and startup-block tests.
- Production paste/activation composition tests.
- Restored destination maximum-length and collision tests under the shared destination module.

## Known limitations

- No loopback listener test can bind in this sandbox.
- `scripts/check.sh` cannot pass its initial `sysctl` query in this sandbox.
- Windows execution has not occurred on BMST.

## Security impact

- v2 is selected and v1 is unreachable from production composition. Refusal happens after one bounded hello frame and before signature, trust, capability, or payload-frame processing.

## Required integrator actions

- Independently review the uncommitted diff, run the exact workspace/listener gates on a host permitting loopback and `sysctl`, and run Windows filesystem gates before commit.

## Recommendation

NO-GO to integrate until the blocked host gates are reproduced on a permitted host and the independent review accepts the diff.
