# Copilot repository instructions

- Follow `AGENTS.md` and the product invariants.
- Keep core/platform/network boundaries intact.
- Never generate code that binds production networking to wildcard interfaces.
- Never add clipboard polling or automatic synchronization.
- Direct push is online-only and at-most-once.
- Reject unpaired peers by default.
- Treat all received text as inert data.
- Add focused tests with every behavior change.
