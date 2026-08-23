# Third-party notices

This source seed references third-party Rust crates but does not vendor their source or binary artifacts. Their names, constraints, purposes, and release-review requirements are recorded in `manifests/DEPENDENCIES.md`, `docs/DEPENDENCY_NOTES.md`, and `deny.toml`.

A release candidate must include a Cargo-generated lockfile and a license report produced from the exact resolved graph. Do not infer that the private project license in `LICENSE.md` applies to dependencies.
