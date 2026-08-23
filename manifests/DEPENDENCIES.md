# Direct dependency inventory

Seed date: 2026-08-23. Exact transitive resolution is intentionally deferred to the first connected local bootstrap, which must generate and commit `Cargo.lock`.

| Dependency | Seed constraint | Purpose | Production boundary |
|---|---:|---|---|
| Slint | 1.17.1 exact | Native window and system tray | UI only |
| Tokio | 1.53.1 | Async direct TCP and bounded timeouts | Network only |
| arboard | 3.6.1 | Explicit clipboard read/write | Dedicated platform worker |
| global-hotkey | 0.8.0 | Windows/macOS/Linux X11 shortcuts | Platform adapter; Wayland excluded |
| redb | 4.2.0 | Durable local receive ledger | Store crate |
| serde / serde_json | current pinned major/minor constraints | Inspectable wire and records | Bounded frame size |
| uuid | current pinned major/minor constraint | Random immutable IDs | Core only |
| tracing | current pinned major/minor constraint | Metadata-only diagnostics | Clipboard bodies forbidden |

Before release, generate `Cargo.lock`, run `cargo tree --duplicates`, `cargo deny check`, and `cargo audit`, then append exact output to a new validation receipt.
