#!/usr/bin/env python3
"""Static integrity checks that do not require the Rust toolchain."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".bat", ".hujson", ".json", ".md", ".py", ".rs", ".sh", ".slint", ".svg", ".toml", ".txt", ".yml", ".yaml"
}
REQUIRED = [
    "START_HERE.md",
    "Cargo.toml",
    "apps/desktop/ui/main.slint",
    "crates/meshelf-core/src/activation.rs",
    "crates/meshelf-core/src/receiver.rs",
    "crates/meshelf-net/src/lib.rs",
    "crates/meshelf-platform/src/clipboard.rs",
    "crates/meshelf-protocol/src/lib.rs",
    "crates/meshelf-store/src/lib.rs",
    "crates/meshelf-tailscale/src/lib.rs",
    "tools/meshelf-sim/src/main.rs",
]
# Every tracked shell script must be executable in the git index, except ones that exist only to be
# sourced. A clone takes file modes from the index, not from anyone's working tree, and the owner's
# synced checkout sets core.fileMode=false, so an executable bit on disk proves nothing about what a
# fresh clone receives. Until this check existed every script was recorded 100644, and the README's
# first command, ./scripts/bootstrap.sh, failed with "permission denied" on a clean clone.
SOURCED_SCRIPTS = {"scripts/rust-env.sh"}
REQUIRED_INVARIANTS = [
    "No controller.",
    "No clipboard surveillance.",
    "Immediate push is online-only.",
    "At-most-once clipboard side effect.",
    "Deny by default.",
]


def fail(message: str) -> None:
    raise RuntimeError(message)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def is_sync_artifact(part: str) -> bool:
    return (
        part.startswith("~syncthing~")
        or part.startswith(".syncthing.")
        or "sync-conflict-" in part
    )


# The owner's private workspace also carries these gitignored control files. A public clone has
# none of them, so their absence is reported as a skip rather than failing the public check.
PRIVATE_REQUIRED = [
    "AGENTS.md",
    "prompts/LAUNCH_PROMPT.md",
    "prompts/work-orders/07_FINAL_AUDIT.md",
    "status/VALIDATION_RECEIPT.md",
]
# Optional, gitignored list of identifiers a maintainer never wants published (one per line).
PRIVACY_DENYLIST = ROOT / ".meshelf-private-denylist"
PRIVATE_DIRS = {".git", "target", "do", "docs", "status", "handoffs", "prompts", "release", "manifests",
                ".worktrees", "build", ".gradle", "node_modules", ".venv"}


def is_private_workspace() -> bool:
    return (ROOT / "AGENTS.md").is_file()


def check_required() -> str | None:
    missing = [relative for relative in REQUIRED if not (ROOT / relative).is_file()]
    if missing:
        fail(f"missing required files: {', '.join(missing)}")
    if not is_private_workspace():
        return "SKIP: private control files and AGENTS.md invariants are absent (public checkout)"
    missing = [relative for relative in PRIVATE_REQUIRED if not (ROOT / relative).is_file()]
    if missing:
        fail(f"missing private control files: {', '.join(missing)}")
    return None


def tracked_files() -> list[Path]:
    if (ROOT / ".git").exists():
        result = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=False)
        if result.returncode == 0:
            return [ROOT / name.decode() for name in result.stdout.split(b"\0") if name]
    return [
        path for path in ROOT.rglob("*")
        if path.is_file() and not any(part in PRIVATE_DIRS for part in path.relative_to(ROOT).parts)
    ]


def check_privacy() -> str | None:
    """Fail when a tracked file or an unpushed commit message names a private identifier.

    The identifiers live only in the owner's gitignored denylist, so the public repo never
    publishes the list it enforces.
    """
    if not PRIVACY_DENYLIST.is_file():
        return "SKIP: privacy denylist not present"
    terms = [
        line.strip().lower()
        for line in PRIVACY_DENYLIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    hits = []
    for path in tracked_files():
        if not path.is_file():
            continue
        text = path.read_bytes().decode("utf-8", "replace").lower()
        for term in terms:
            if term in text:
                hits.append(f"{path.relative_to(ROOT)} contains a denylisted identifier")
                break
    if (ROOT / ".git").exists():
        upstream = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--verify", "--quiet", "refs/remotes/origin/main"],
            capture_output=True, text=True, check=False,
        )
        revision = "refs/remotes/origin/main..HEAD" if upstream.returncode == 0 else "-1"
        log = subprocess.run(
            ["git", "-C", str(ROOT), "log", "--format=%h%x00%B%x01", revision],
            capture_output=True, text=True, check=False,
        )
        for entry in log.stdout.split("\x01"):
            commit, _, message = entry.strip().partition("\0")
            if commit and any(term in message.lower() for term in terms):
                hits.append(f"commit {commit} message contains a denylisted identifier")
    if hits:
        fail("private identifiers found (see .meshelf-private-denylist): " + "; ".join(hits[:20]))
    return None


def check_executable_modes() -> str | None:
    """Return an explicit skip notice outside a git checkout; fail on any non-executable script."""
    if not (ROOT / ".git").exists():
        return "SKIP: executable-mode check needs a git checkout; this tree has no .git"
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-s", "--", "*.sh"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail(f"git ls-files failed while checking script modes: {result.stderr.strip()}")
    wrong = []
    for line in result.stdout.splitlines():
        meta, _, relative = line.partition("\t")
        if relative in SOURCED_SCRIPTS:
            continue
        mode = meta.split()[0]
        if mode != "100755":
            wrong.append(f"{relative} ({mode})")
    if wrong:
        fail(
            "shell scripts are not executable in the git index, so a fresh clone cannot run them: "
            + ", ".join(wrong)
            + ". Fix with: git update-index --chmod=+x <path>"
        )
    return None


def check_text_and_structured_files() -> None:
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or any(
            part
            in {
                ".git",
                "target",
                "__pycache__",
                ".venv",
                "do",
                "status",
                "_icon_work",
                "release",
            }
            or is_sync_artifact(part)
            for part in path.relative_to(ROOT).parts
        ) or path.name in {"AGENTS.md", "CLAUDE.md", ".DS_Store", ".env"} or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {".editorconfig", ".gitattributes", ".gitignore"}:
            data = path.read_bytes()
            if b"\x00" in data:
                fail(f"NUL byte in text file: {path.relative_to(ROOT)}")
            try:
                data.decode("utf-8")
            except UnicodeDecodeError as error:
                fail(f"non-UTF-8 text file {path.relative_to(ROOT)}: {error}")
        if path.suffix == ".toml":
            try:
                tomllib.loads(path.read_text(encoding="utf-8"))
            except Exception as error:
                fail(f"invalid TOML {path.relative_to(ROOT)}: {error}")
        if path.suffix == ".json":
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except Exception as error:
                fail(f"invalid JSON {path.relative_to(ROOT)}: {error}")


def check_workspace() -> None:
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    members = workspace.get("workspace", {}).get("members", [])
    if not members:
        fail("workspace has no members")
    for member in members:
        cargo = ROOT / member / "Cargo.toml"
        if not cargo.is_file():
            fail(f"workspace member lacks Cargo.toml: {member}")


def check_invariants() -> None:
    if is_private_workspace():
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        for invariant in REQUIRED_INVARIANTS:
            if invariant not in agents:
                fail(f"binding invariant missing from AGENTS.md: {invariant}")

    rust_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(ROOT.rglob("*.rs"))
        if "target" not in path.parts
    )
    forbidden = {
        r"TcpListener::bind\(\s*\(\s*\[0,\s*0,\s*0,\s*0\]": "production all-interface bind",
        r"allow_all": "permissive trust helper",
    }
    for pattern, description in forbidden.items():
        if re.search(pattern, rust_source, flags=re.IGNORECASE | re.DOTALL):
            fail(f"forbidden pattern found: {description}")

    net = (ROOT / "crates/meshelf-net/src/lib.rs").read_text(encoding="utf-8")
    if "pub struct DenyAll" not in net or "bind_discovered_tailscale_address" not in net:
        fail("network deny-by-default/private-bind seams are missing")
    activation = (ROOT / "crates/meshelf-core/src/activation.rs").read_text(encoding="utf-8")
    if "UncertainNoReplay" not in activation or "ApplyingClipboard" not in activation:
        fail("at-most-once uncertain-boundary handling is missing")
    clipboard = (ROOT / "crates/meshelf-platform/src/clipboard.rs").read_text(encoding="utf-8")
    explicit_read = clipboard.split("ClipboardCommand::Read(response) =>", 1)
    if (
        len(explicit_read) != 2
        or "clipboard.get().file_list()" not in explicit_read[1]
        or ".get_text()" not in explicit_read[1]
    ):
        fail("clipboard reads must remain isolated to the explicit Read command")


def main() -> int:
    argparse.ArgumentParser().parse_args()
    try:
        notices = [check_required(), check_executable_modes()]
        check_text_and_structured_files()
        check_workspace()
        check_invariants()
        notices.append(check_privacy())
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    for notice in notices:
        if notice:
            print(notice)
    print("PASS: meshelf repository structure and integrity checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
