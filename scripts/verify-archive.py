#!/usr/bin/env python3
"""Verify ZIP CRC, safe names, root folder, and embedded SHA-256 manifest."""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import PurePosixPath


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            bad = archive.testzip()
            if bad:
                raise RuntimeError(f"CRC failure: {bad}")
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise RuntimeError("archive contains duplicate member names")
            if not names or not all(name.startswith("meshelf/") for name in names):
                raise RuntimeError("archive does not have one meshelf/ root")
            for name in names:
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts or "\\" in name:
                    raise RuntimeError(f"unsafe archive path: {name}")
            manifest_name = "meshelf/manifests/FILES.sha256"
            manifest = archive.read(manifest_name).decode("utf-8")
            expected = {}
            for line in manifest.splitlines():
                if not line or line.startswith("#"):
                    continue
                digest, relative = line.split("  ", 1)
                expected[relative] = digest
            expected_members = {f"meshelf/{relative}" for relative in expected}
            expected_members.add(manifest_name)
            actual_members = set(names)
            missing = sorted(expected_members - actual_members)
            unexpected = sorted(actual_members - expected_members)
            if missing:
                raise RuntimeError(f"manifested archive members are missing: {missing[:5]}")
            if unexpected:
                raise RuntimeError(f"unmanifested archive members exist: {unexpected[:5]}")
            for relative, digest in expected.items():
                data = archive.read(f"meshelf/{relative}")
                actual = hashlib.sha256(data).hexdigest()
                if actual != digest:
                    raise RuntimeError(f"embedded manifest mismatch: {relative}")
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: ZIP CRC, paths, and {len(expected)} embedded hashes verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
