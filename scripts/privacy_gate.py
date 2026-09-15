#!/usr/bin/env python3
"""Fail closed on owner-private identifiers without storing them in Git."""

from __future__ import annotations

import argparse
import re
import subprocess
import tempfile
from pathlib import Path


class GateError(RuntimeError):
    pass


def git(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout


def nul_items(data: bytes) -> list[str]:
    return [item.decode("utf-8", "surrogateescape") for item in data.split(b"\0") if item]


def find_denylist(root: Path) -> Path | None:
    for candidate in (root / ".private-denylist", *sorted(root.glob(".*-private-denylist"))):
        if candidate.is_file():
            return candidate
    return None


def load_terms(root: Path) -> list[bytes]:
    denylist = find_denylist(root)
    if denylist is None:
        raise GateError("private denylist is missing")
    terms = [
        line.strip().encode("utf-8").lower()
        for line in denylist.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not terms:
        raise GateError("private denylist has no active terms")
    return terms


def hits(label: str, payload: bytes, terms: list[bytes]) -> list[str]:
    lowered = payload.lower()
    for term in terms:
        if len(term) <= 4:
            pattern = rb"(?<![a-z0-9])" + re.escape(term) + rb"(?![a-z0-9])"
            if re.search(pattern, lowered):
                return [label]
        elif term in lowered:
            return [label]
    return []


def scan_cached(root: Path, terms: list[bytes]) -> list[str]:
    found: list[str] = []
    for path in nul_items(git(root, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR")):
        found += hits(f"staged path {path}", path.encode("utf-8", "surrogateescape"), terms)
        found += hits(f"staged blob {path}", git(root, "show", f":{path}"), terms)
    return found


def scan_repo(root: Path, terms: list[bytes]) -> list[str]:
    found: list[str] = []
    for path in nul_items(git(root, "ls-files", "-z")):
        found += hits(f"tracked path {path}", path.encode("utf-8", "surrogateescape"), terms)
        found += hits(f"tracked blob {path}", git(root, "show", f"HEAD:{path}"), terms)
    return found


def scan_reachable(root: Path, terms: list[bytes]) -> list[str]:
    found: list[str] = []
    objects: set[str] = set()
    for line in git(root, "rev-list", "--objects", "--all").decode().splitlines():
        sha, _, path = line.partition(" ")
        objects.add(sha)
        if path:
            found += hits(f"historical path {path}", path.encode(), terms)
    refs = git(root, "for-each-ref", "--format=%(refname)%00%(objectname)%00%(objecttype)")
    for row in refs.splitlines():
        fields = row.split(b"\0")
        if len(fields) < 2:
            continue
        refname, object_id = fields[0], fields[1]
        objects.add(object_id.decode())
        found += hits(f"ref {refname.decode('utf-8', 'replace')}", refname, terms)
    proc = subprocess.Popen(
        ["git", "cat-file", "--batch"], cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    assert proc.stdin is not None and proc.stdout is not None
    for sha in sorted(objects):
        proc.stdin.write((sha + "\n").encode())
        proc.stdin.flush()
        header = proc.stdout.readline().split()
        if len(header) < 3:
            continue
        kind, size = header[1].decode(), int(header[2])
        found += hits(f"object {sha[:12]} ({kind})", proc.stdout.read(size), terms)
        proc.stdout.read(1)
    proc.stdin.close()
    proc.wait()
    return found


def self_test() -> None:
    terms = [b"synthetic-private-token"]
    source = Path(__file__).read_bytes()
    checks = [
        hits("checker source", source, terms),
        hits("case variant", b"SYNTHETIC-PRIVATE-TOKEN", terms),
        hits("binary", b"\0synthetic-private-token\0", terms),
        hits("filename", b"synthetic-private-token.txt", terms),
    ]
    if not all(checks):
        raise GateError("synthetic byte/path self-test failed")
    if [line for line in ["# comment", "  "] if line.strip() and not line.lstrip().startswith("#")]:
        raise GateError("comments-only denylist self-test failed")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        git(root, "init", "-q")
        git(root, "config", "user.name", "Privacy Gate")
        git(root, "config", "user.email", "privacy-gate@example.invalid")
        git(root, "config", "core.hooksPath", "/dev/null")
        (root / "index-only.txt").write_bytes(b"synthetic-private-token")
        git(root, "add", "index-only.txt")
        (root / "index-only.txt").write_bytes(b"clean")
        if not scan_cached(root, terms):
            raise GateError("staged-index self-test failed")
        git(root, "add", "index-only.txt")
        git(root, "commit", "-qm", "synthetic-private-token commit message")
        git(root, "tag", "-am", "synthetic-private-token tag message", "synthetic-tag")
        git(root, "branch", "synthetic-private-token-ref")
        if not scan_reachable(root, terms):
            raise GateError("commit/tag/ref self-test failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-ci", action="store_true")
    parser.add_argument("--require-private", action="store_true")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--cached", action="store_true")
    scope.add_argument("--repo", action="store_true")
    scope.add_argument("--outgoing", action="store_true")
    args = parser.parse_args()
    try:
        root = Path(git(Path.cwd(), "rev-parse", "--show-toplevel").decode().strip())
    except subprocess.CalledProcessError:
        root = Path(git(Path.cwd(), "rev-parse", "--git-dir").decode().strip()).resolve()
    try:
        if args.public_ci:
            if args.require_private or args.cached or args.repo or args.outgoing:
                raise GateError("--public-ci cannot use private scanning flags")
            self_test()
            print("privacy gate: public CI self-tests passed")
            return 0
        if not args.require_private or not (args.cached or args.repo or args.outgoing):
            raise GateError("use --public-ci or --require-private with one scan scope")
        terms = load_terms(root)
        found = scan_cached(root, terms) if args.cached else (
            scan_repo(root, terms) if args.repo else scan_reachable(root, terms)
        )
        if found:
            raise GateError("private identifier found: " + "; ".join(found[:20]))
        print("privacy gate: clean")
        return 0
    except (GateError, subprocess.CalledProcessError) as error:
        print(f"privacy gate: FAIL — {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
