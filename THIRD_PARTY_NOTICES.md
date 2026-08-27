# Third-party notices

This project uses third-party Rust crates but does not vendor their source or binary artifacts. The
exact resolved dependency graph is recorded in `Cargo.lock`; release review is configured in
`deny.toml`.

A release candidate must include a Cargo-generated lockfile and a license report produced from the exact resolved graph. The MIT license in `LICENSE.md` applies to meshelf's source, not to its dependencies.
