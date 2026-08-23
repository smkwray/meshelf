#!/usr/bin/env python3
"""Static integrity checks that do not require the Rust toolchain."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests" / "FILES.sha256"
TEXT_SUFFIXES = {
    ".bat", ".hujson", ".json", ".md", ".py", ".rs", ".sh", ".slint", ".svg", ".toml", ".txt", ".yml", ".yaml"
}
REQUIRED = [
    "AGENTS.md",
    "START_HERE.md",
    "Cargo.toml",
    "apps/desktop/ui/main.slint",
    "crates/meshelf-core/src/receiver.rs",
    "crates/meshelf-net/src/lib.rs",
    "crates/meshelf-platform/src/clipboard.rs",
    "crates/meshelf-protocol/src/lib.rs",
    "crates/meshelf-store/src/lib.rs",
    "crates/meshelf-tailscale/src/lib.rs",
    "tools/meshelf-sim/src/main.rs",
    "prompts/LAUNCH_PROMPT.md",
    "prompts/work-orders/07_FINAL_AUDIT.md",
    "status/VALIDATION_RECEIPT.md",
]
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
    return part.startswith("~syncthing~") or "sync-conflict-" in part


def check_required() -> None:
    missing = [relative for relative in REQUIRED if not (ROOT / relative).is_file()]
    if missing:
        fail(f"missing required files: {', '.join(missing)}")


def check_text_and_structured_files() -> None:
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or any(
            part in {".git", "target", "__pycache__", ".venv", "do", "status", "_icon_work"}
            or is_sync_artifact(part)
            for part in path.relative_to(ROOT).parts
        ) or path.name in {"AGENTS.md", "CLAUDE.md", ".env"} or path.suffix in {".pyc", ".pyo"}:
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
    receiver = (ROOT / "crates/meshelf-core/src/receiver.rs").read_text(encoding="utf-8")
    if "UncertainNoReplay" not in receiver or "ReceivePhase::Applying" not in receiver:
        fail("at-most-once uncertain-boundary handling is missing")
    clipboard = (ROOT / "crates/meshelf-platform/src/clipboard.rs").read_text(encoding="utf-8")
    if clipboard.count("clipboard.get_text()") != 1 or "ClipboardCommand::Read" not in clipboard:
        fail("clipboard reads must remain isolated to the explicit Read command")


def parse_manifest() -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        expected, relative = line.split("  ", 1)
        entries[relative] = expected
    return entries


def check_manifest(allow_stale: bool) -> None:
    if not MANIFEST.is_file():
        if allow_stale:
            print("WARN: internal manifest has not been generated")
            return
        fail("manifests/FILES.sha256 is missing")
    entries = parse_manifest()
    mismatches: list[str] = []
    for relative, expected in entries.items():
        path = ROOT / relative
        if not path.is_file():
            mismatches.append(f"missing {relative}")
        elif digest(path) != expected:
            mismatches.append(f"changed {relative}")
    expected_paths = {
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_file()
        and path != MANIFEST
        and path.suffix not in {".pyc", ".pyo"}
        and path.name not in {"AGENTS.md", "CLAUDE.md", ".env"}
        and not any(
            part in {".git", "target", ".idea", ".vscode", "local-data", "__pycache__", ".venv", "do", "status", "_icon_work"}
            or is_sync_artifact(part)
            for part in path.relative_to(ROOT).parts
        )
    }
    extra = sorted(expected_paths - entries.keys())
    mismatches.extend(f"unmanifested {relative}" for relative in extra)
    if mismatches:
        if allow_stale:
            print("WARN: manifest is stale: " + "; ".join(mismatches[:10]))
        else:
            fail("manifest verification failed: " + "; ".join(mismatches[:20]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-stale-manifest", action="store_true")
    args = parser.parse_args()
    try:
        check_required()
        check_text_and_structured_files()
        check_workspace()
        check_invariants()
        check_manifest(args.allow_stale_manifest)
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    files = sum(
        1
        for path in ROOT.rglob("*")
        if path.is_file()
        and path.suffix not in {".pyc", ".pyo"}
        and "__pycache__" not in path.parts
        and ".venv" not in path.parts
        and "do" not in path.parts
        and "status" not in path.parts
        and "_icon_work" not in path.parts
        and not any(is_sync_artifact(part) for part in path.parts)
    )
    print(f"PASS: meshelf repository structure and integrity checks ({files} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
