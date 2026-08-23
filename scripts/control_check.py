#!/usr/bin/env python3
"""Control-file integrity checker.

Checks the private control surface (AGENTS.md, CLAUDE.md, do/state.md,
do/decisions.md) plus the tracked surfaces that cite owner-decision IDs.
Standard library only.

    control_check.py [PROJECT_ROOT]   check a project (default: cwd)
    control_check.py --selftest       prove every rule fires on a known defect
    control_check.py --strict ...     exit 1 on MIGRATE as well as FAIL

Severities:
    FAIL     integrity defect that is wrong today
    MIGRATE  format non-compliance, expected until a project is migrated
    WARN     approaching a budget, or an advisory
"""

from __future__ import annotations

import ast
import hashlib
import re
import sys
from pathlib import Path

# --- shared invariant block --------------------------------------------------
INV_OPEN_ANY = "<!-- project-template-invariants"
INV_CLOSE = "<!-- /project-template-invariants -->"
INV_STAMP = re.compile(r"<!-- project-template-invariants version=(\d+) sha256=([0-9a-f]{64}) -->")


def invariant_body(text: str) -> str | None:
    """Text between the markers, exclusive. None if the block is absent."""
    i = text.find(INV_OPEN_ANY)
    if i < 0:
        return None
    j = text.find("-->", i)
    k = text.find(INV_CLOSE, j)
    if j < 0 or k < 0:
        return None
    return text[j + 3:k].strip("\n")


def body_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()

# --- budgets (bytes) ---------------------------------------------------------
AGENTS_WARN, AGENTS_FAIL = 6 * 1024, 12 * 1024
STATE_WARN, STATE_FAIL = 12 * 1024, 24 * 1024
COMBINED_FAIL = 32 * 1024

# --- decision identifiers ----------------------------------------------------
# Permissive: must catch every legacy shape actually observed, including the
# underscore form embedded in a longer token (resolved_D_20260716_001).
ID_SCAN = re.compile(r"(?<![A-Za-z0-9])(?:OWNER|[OD])[-_]20\d{6}[-_][A-Za-z0-9_.]*[A-Za-z0-9_]")
# Canonical for new entries.
ID_CANON = re.compile(r"^D-20\d{6}-\d{2}$")
HEADING = re.compile(r"^(#{2,6})\s+((?:OWNER|[OD])[-_]20\d{6}[-_][A-Za-z0-9_.]+)\s*(.*)$")
FIELD = re.compile(r"^(Decision|Source|Status|Supersedes|Condition|Basis):", re.M)
GLOSS = re.compile(r"^(Kernel|Effect|Scope note|Consequence|Effect note):", re.M | re.I)
STATUS_OK = re.compile(r"^(active|deferred|superseded[- ]by\s+\S+)", re.I)

# Config keys under which a decision ID is provenance, not authority.
PROVENANCE_KEYS = re.compile(
    r"(source|provenance|ref|refs|note|notes|comment|rationale|reason|origin|authority_ref)$",
    re.I,
)
CODE_EXT = {".py"}
CONFIG_EXT = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg"}
# Live executable surfaces only. Generated evidence, archives, assessments, and
# worktrees legitimately mention historical IDs and are not authority.
SCAN_ROOTS = ("src", "configs", "config", "scripts", "tests")
SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", "do", "docs",
    "var", "data", "outputs", "dist", "build", "archive", ".worktrees",
    ".claude", "artifacts", "assess", "receipts", "evidence", "fixtures",
}


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, sev: str, check: str, msg: str) -> None:
        self.rows.append((sev, check, msg))

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for sev, _, _ in self.rows:
            out[sev] = out.get(sev, 0) + 1
        return out

    def render(self) -> str:
        if not self.rows:
            return "  (clean)"
        order = {"FAIL": 0, "MIGRATE": 1, "WARN": 2}
        rows = sorted(self.rows, key=lambda r: (order.get(r[0], 3), r[1]))
        return "\n".join(f"  {s:<7} {c:<26} {m}" for s, c, m in rows)


# --- individual checks -------------------------------------------------------

def check_import(root: Path, rep: Report) -> None:
    p = root / "CLAUDE.md"
    if not p.is_file():
        rep.add("FAIL", "control_import", "CLAUDE.md missing")
        return
    if p.read_text(encoding="utf-8", errors="replace").strip() != "@AGENTS.md":
        rep.add("FAIL", "control_import", "CLAUDE.md is not exactly '@AGENTS.md'")


def check_invariants(root: Path, rep: Report) -> None:
    """The shared block must be present, stamped, and byte-identical to its stamp.

    Without this, a project can report clean while never having adopted the
    control design at all — the failure that let hearken pass at 0/0/0.
    """
    p = root / "AGENTS.md"
    if not p.is_file():
        rep.add("FAIL", "control_invariants", "AGENTS.md missing")
        return
    text = p.read_text(encoding="utf-8", errors="replace")
    # INV_CLOSE contains a '/' so it is not a substring of INV_OPEN_ANY; count directly.
    n_open = text.count(INV_OPEN_ANY)
    n_close = text.count(INV_CLOSE)

    if n_open == 0 and n_close == 0:
        # A project that has already migrated its state but not adopted the
        # shared block is inconsistent, not merely legacy.
        state = root / "do" / "state.md"
        migrated = state.is_file() and "schema: project.state.v1" in state.read_text(
            encoding="utf-8", errors="replace")
        rep.add(
            "FAIL" if migrated else "MIGRATE", "control_invariants",
            "no shared invariant block — run sync_project_controls.sh --adopt",
        )
        return
    if n_open != 1 or n_close != 1:
        rep.add("FAIL", "control_invariants",
                f"expected exactly one invariant block, found {n_open} open / {n_close} close")
        return

    m = INV_STAMP.search(text)
    if not m:
        rep.add("FAIL", "control_invariants",
                "invariant marker carries no version/sha256 stamp — run --apply")
        return
    body = invariant_body(text)
    if body is None:
        rep.add("FAIL", "control_invariants", "invariant block is malformed")
        return
    if body_hash(body) != m.group(2):
        rep.add("FAIL", "control_invariants",
                f"invariant block (v{m.group(1)}) was hand-edited — hash mismatch; "
                f"--apply restores it")


def check_budgets(root: Path, rep: Report) -> None:
    a = root / "AGENTS.md"
    s = root / "do" / "state.md"
    a_b = a.stat().st_size if a.is_file() else 0
    s_b = s.stat().st_size if s.is_file() else 0

    def fmt(n: int) -> str:
        return f"{n:,}B (~{n/4000:.1f}k tok)"

    if a_b > AGENTS_FAIL:
        rep.add("FAIL", "control_budget", f"AGENTS.md {fmt(a_b)} over {AGENTS_FAIL//1024}KiB")
    elif a_b > AGENTS_WARN:
        rep.add("WARN", "control_budget", f"AGENTS.md {fmt(a_b)} over target {AGENTS_WARN//1024}KiB")
    if s_b > STATE_FAIL:
        rep.add("FAIL", "control_budget", f"do/state.md {fmt(s_b)} over {STATE_FAIL//1024}KiB")
    elif s_b > STATE_WARN:
        rep.add("WARN", "control_budget", f"do/state.md {fmt(s_b)} over target {STATE_WARN//1024}KiB")
    if a_b + s_b > COMBINED_FAIL:
        rep.add(
            "FAIL", "control_budget",
            f"always-loaded {fmt(a_b + s_b)} over combined {COMBINED_FAIL//1024}KiB",
        )


def parse_decisions(text: str) -> tuple[list[dict], list[tuple[int, str]]]:
    """Split decisions.md into records. Returns (records, heading_levels)."""
    lines = text.splitlines()
    marks: list[tuple[int, str, str, str]] = []  # (lineno, hashes, id, title)
    for i, ln in enumerate(lines, 1):
        m = HEADING.match(ln)
        if m:
            marks.append((i, m.group(1), m.group(2), m.group(3)))
    records = []
    for idx, (ln, hashes, did, title) in enumerate(marks):
        end = marks[idx + 1][0] - 1 if idx + 1 < len(marks) else len(lines)
        body = "\n".join(lines[ln:end])
        records.append({"line": ln, "level": len(hashes), "id": did, "title": title, "body": body})
    return records, [(r["line"], "#" * r["level"]) for r in records]


def check_decisions(root: Path, rep: Report) -> dict[str, str]:
    """Returns {decision_id: status} for the reference checker."""
    p = root / "do" / "decisions.md"
    if not p.is_file():
        return {}
    text = p.read_text(encoding="utf-8", errors="replace")
    records, levels = parse_decisions(text)
    if not records:
        return {}

    declared: dict[str, str] = {}
    seen_lines: dict[str, int] = {}
    levelset = {lv for _, lv in levels}
    if len(levelset) > 1:
        rep.add(
            "FAIL", "control_decisions",
            f"mixed heading levels {sorted(levelset)} — records below the shallowest are "
            f"outside the section structure",
        )

    prev_date = ""
    for r in records:
        did, ln, body = r["id"], r["line"], r["body"]
        if did in seen_lines:
            rep.add("FAIL", "control_decisions", f"duplicate ID {did} (also line {seen_lines[did]})")
        seen_lines[did] = ln

        n_dec = len(re.findall(r"^Decision:", body, re.M))
        n_src = len(re.findall(r"^Source:", body, re.M))
        if n_src > 1:
            # A second Source: means a distinct decision lost its heading.
            rep.add(
                "FAIL", "control_decisions",
                f"{did} (line {ln}) absorbed another entry: {n_dec} Decision:/{n_src} Source: "
                f"fields under one heading",
            )
        elif n_dec > 1:
            # One decision recorded as several quoted parts: fold into one field.
            rep.add(
                "MIGRATE", "control_decisions",
                f"{did} (line {ln}) has {n_dec} Decision: fields under one Source — fold into one",
            )

        if not ID_CANON.match(did):
            rep.add("MIGRATE", "control_decisions", f"{did} (line {ln}) not canonical D-YYYYMMDD-NN")

        m = re.search(r"20(\d{6})", did)
        date = m.group(1) if m else ""
        if date and prev_date and date < prev_date:
            rep.add("MIGRATE", "control_decisions", f"{did} (line {ln}) out of chronological order")
        prev_date = max(prev_date, date)

        if n_dec == 0:
            rep.add("MIGRATE", "control_decisions", f"{did} (line {ln}) has no 'Decision:' field")
        if n_src == 0 and "Source:" not in body:
            rep.add("MIGRATE", "control_decisions", f"{did} (line {ln}) has no 'Source:' field")

        g = GLOSS.search(body)
        if g:
            rep.add(
                "MIGRATE", "control_decisions",
                f"{did} (line {ln}) carries model gloss field '{g.group(1)}:' in the authority record",
            )

        sm = re.search(r"^Status:\s*(.+)$", body, re.M)
        status_txt = sm.group(1).strip() if sm else ""
        if not status_txt:
            sm2 = re.search(r"Status:\s*([A-Za-z][^.\n]*)", body)
            status_txt = sm2.group(1).strip() if sm2 else ""
        if not status_txt:
            rep.add("MIGRATE", "control_decisions", f"{did} (line {ln}) has no parseable Status")
            declared[did] = "unknown"
        else:
            if not STATUS_OK.match(status_txt):
                rep.add(
                    "MIGRATE", "control_decisions",
                    f"{did} (line {ln}) status not in vocabulary: {status_txt[:40]!r}",
                )
            declared[did] = status_txt.lower()

    # supersession targets must exist
    for r in records:
        for tgt in re.findall(
                r"superseded[- ]by\s+((?:OWNER|[OD])[-_]20\d{6}[-_][A-Za-z0-9_.]*[A-Za-z0-9_])",
                r["body"], re.I):
            if tgt not in declared:
                rep.add("FAIL", "control_decisions",
                        f"{r['id']} superseded by {tgt}, which is not declared")
    return declared


def check_refs(root: Path, declared: dict[str, str], rep: Report) -> None:
    """Every ID cited from live control surfaces must resolve and be current."""
    targets: list[Path] = []
    for rel in ("AGENTS.md", "do/state.md"):
        p = root / rel
        if p.is_file():
            targets.append(p)
    od = root / "do" / "orders"
    if od.is_dir():
        targets.extend(sorted(od.glob("*.md")))

    for p in targets:
        text = p.read_text(encoding="utf-8", errors="replace")
        for ln, line in enumerate(text.splitlines(), 1):
            for did in set(ID_SCAN.findall(line)):
                where = f"{p.relative_to(root)}:{ln}"
                if did not in declared:
                    rep.add("FAIL", "control_refs", f"{where} cites {did} — resolves to no entry")
                elif declared[did].startswith("superseded"):
                    rep.add("WARN", "control_refs", f"{where} cites {did} — superseded")


def check_executable_gates(root: Path, rep: Report) -> None:
    """Owner-decision IDs must never determine executable behaviour."""
    candidates: list[Path] = []
    for name in SCAN_ROOTS:
        base = root / name
        if base.is_dir():
            candidates.extend(base.rglob("*"))
    for path in sorted(candidates):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        ext = path.suffix.lower()
        rel = path.relative_to(root)
        if ext in CODE_EXT:
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            except (SyntaxError, ValueError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Compare):
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            if ID_SCAN.search(sub.value):
                                rep.add(
                                    "FAIL", "control_exec_gate",
                                    f"{rel}:{getattr(node, 'lineno', '?')} runtime comparison "
                                    f"against decision ID {sub.value!r}",
                                )
        elif ext in CONFIG_EXT:
            for ln, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                ids = ID_SCAN.findall(line)
                if not ids:
                    continue
                key = re.match(r"\s*-?\s*([A-Za-z0-9_.]+)\s*:", line)
                provenance = bool(key and PROVENANCE_KEYS.search(key.group(1)))
                if not provenance:
                    rep.add(
                        "FAIL", "control_exec_gate",
                        f"{rel}:{ln} decision ID {ids[0]} outside a provenance key",
                    )


def check_state_shape(root: Path, rep: Report) -> None:
    p = root / "do" / "state.md"
    if not p.is_file():
        # A project may legitimately run without do/ (see INIT.md "When NOT to
        # initialize"). A do/ that exists without state.md is an incomplete
        # install, not corruption.
        if (root / "do").is_dir():
            rep.add("MIGRATE", "control_state", "do/ exists but do/state.md is missing")
        return
    text = p.read_text(encoding="utf-8", errors="replace")
    allowed = {
        "current verified state", "next work",
        "visible off or interim states", "owner decisions needed",
    }
    h2 = [m.group(1).strip() for m in re.finditer(r"^##\s+(.+)$", text, re.M)]
    extra = [h for h in h2 if h.lower().rstrip(":") not in allowed]
    if extra:
        rep.add(
            "MIGRATE", "control_state",
            f"{len(extra)} non-canonical H2 section(s), first: {extra[0][:60]!r}",
        )
    if not text.startswith("---"):
        rep.add("MIGRATE", "control_state", "no YAML front matter")


# --- driver ------------------------------------------------------------------

def run(root: Path) -> Report:
    rep = Report()
    check_import(root, rep)
    check_invariants(root, rep)
    check_budgets(root, rep)
    declared = check_decisions(root, rep)
    check_refs(root, declared, rep)
    check_state_shape(root, rep)
    check_executable_gates(root, rep)
    return rep


def _stamped_agents(body: str = "- a shared rule") -> str:
    # Hash the body exactly as invariant_body() will read it back.
    return (f"# t\n\n<!-- project-template-invariants version=1 sha256={body_hash(body)} -->\n"
            f"{body}\n{INV_CLOSE}\n")


SELFTEST_CASES = [
    ("control_import", {"CLAUDE.md": "@agents.md\n"}),
    ("control_invariants", {"AGENTS.md": "# t\nno block here\n"}),          # never adopted
    ("control_invariants", {                                                # hand-edited body
        "AGENTS.md": _stamped_agents().replace("- a shared rule", "- tampered"),
    }),
    ("control_invariants", {                                                # unstamped marker
        "AGENTS.md": f"# t\n\n<!-- project-template-invariants version=1 -->\n- x\n{INV_CLOSE}\n",
    }),
    ("control_invariants", {                                                # duplicated block
        "AGENTS.md": _stamped_agents() + _stamped_agents(),
    }),
    ("control_decisions", {  # absorbed entry (ratewall D-20260725-01)
        "do/decisions.md":
            "## D-20260727-01 — a\n\nDecision: x\n\nSource: owner. Status: active.\n\n"
            "Decision: y\n\nSource: owner. Status: active.\n",
    }),
    ("control_decisions", {  # duplicate suffix + mixed heading levels (statera)
        "do/decisions.md":
            "### O-20260727-25 — a\n\nDecision: x\n\nSource: o. Status: active.\n\n"
            "## O-20260731-25 — b\n\nDecision: y\n\nSource: o. Status: active.\n",
    }),
    ("control_decisions", {  # model gloss in the authority record
        "do/decisions.md":
            "## D-20260801-01 — a\n\nDecision: x\n\nSource: o. Status: active.\n\nEffect: model says y\n",
    }),
    ("control_refs", {  # dangling live reference (statera OWNER-20260718-D)
        "do/decisions.md": "## D-20260801-01 — a\n\nDecision: x\n\nSource: o. Status: active.\n",
        "do/state.md": "## Current verified state\n\n- per OWNER-20260718-D\n",
    }),
    ("control_exec_gate", {  # hyphen form (statera :258)
        "src/m.py": 'x = {}\nif x.get("owner_authority") != "OWNER-20260716-A.ruling_3":\n    pass\n',
    }),
    ("control_exec_gate", {  # underscore form the original regex missed (statera :280)
        "src/m.py": 'x = {}\nif x.get("s") != "resolved_D_20260716_001":\n    pass\n',
    }),
    ("control_budget", {"AGENTS.md": "x" * (AGENTS_FAIL + 1)}),
]


def selftest() -> int:
    import shutil
    import tempfile

    failures = 0
    for i, (expect, files) in enumerate(SELFTEST_CASES, 1):
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
            (tmp / "AGENTS.md").write_text(_stamped_agents(), encoding="utf-8")
            (tmp / "do").mkdir()
            (tmp / "do" / "state.md").write_text(
                "---\nschema: x\n---\n\n## Current verified state\n\n- ok\n", encoding="utf-8")
            for rel, content in files.items():
                dst = tmp / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(content, encoding="utf-8")
            rep = run(tmp)
            fired = {c for s, c, _ in rep.rows if s in ("FAIL", "MIGRATE")}
            ok = expect in fired
            print(f"  {'PASS' if ok else 'FAIL'}  case {i}: {expect}"
                  f"{'' if ok else f'  (fired: {sorted(fired) or None})'}")
            if not ok:
                failures += 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # clean fixture must produce no FAIL
    tmp = Path(tempfile.mkdtemp())
    try:
        (tmp / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
        (tmp / "AGENTS.md").write_text(_stamped_agents(), encoding="utf-8")
        (tmp / "do").mkdir()
        (tmp / "do" / "state.md").write_text(
            "---\nschema: x\n---\n\n## Current verified state\n\n- ok\n", encoding="utf-8")
        (tmp / "do" / "decisions.md").write_text(
            "# t\n\n## D-20260801-01 — a\n\nDecision: x\n\nSource: owner chat.\nStatus: active\n",
            encoding="utf-8")
        rep = run(tmp)
        hard = [r for r in rep.rows if r[0] == "FAIL"]
        ok = not hard
        print(f"  {'PASS' if ok else 'FAIL'}  case {len(SELFTEST_CASES)+1}: clean fixture is clean"
              f"{'' if ok else f'  ({hard})'}")
        if not ok:
            failures += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\nselftest: {failures} failing" if failures else "\nselftest: all rules fire")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    strict = "--strict" in argv
    args = [a for a in argv if not a.startswith("--")]
    roots = [Path(a).expanduser().resolve() for a in args] or [Path.cwd()]

    worst = 0
    for root in roots:
        rep = run(root)
        c = rep.counts()
        print(f"\n{root.name}  "
              f"FAIL {c.get('FAIL',0)}  MIGRATE {c.get('MIGRATE',0)}  WARN {c.get('WARN',0)}")
        print(rep.render())
        if c.get("FAIL"):
            worst = 1
        elif strict and c.get("MIGRATE"):
            worst = 1
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
