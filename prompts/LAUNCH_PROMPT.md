# meshelf local-agent launch prompt

You are continuing the private cross-platform application **meshelf** from an agent-ready seed.

Read, in order:

1. `AGENTS.md`
2. `docs/00_PRODUCT_CONTRACT.md`
3. `docs/01_ARCHITECTURE.md`
4. `docs/02_PROTOCOL.md`
5. `docs/03_SECURITY.md`
6. The private `do/state.md` note when working in a synced development workspace.
7. your assigned file under `prompts/work-orders/`

Architecture is settled: all devices are symmetric peers; there is no controller or canonical host. Ordinary clipboard copies do nothing. A direct clipboard push is initiated only by an explicit meshelf action, is online-only, and must never be replayed later into the clipboard. File transfer is frozen until text v1 is accepted.

Work only in your assigned ownership lane. Begin by running the narrow existing tests. Repair compile defects in your owned files, implement the work order, add adversarial tests, run the required validation, and fill `handoffs/TEMPLATE.md` with exact commands and results. Do not weaken deny-by-default trust or claim unrun platform behavior.
