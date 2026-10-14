#!/usr/bin/env python3
"""Create or verify the SHA-256 manifest for this publication folder."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "PACKAGE_MANIFEST.json"
GENERATED_SUFFIXES = {".aux", ".bbl", ".blg", ".fls", ".log", ".out", ".toc", ".pyc"}
GENERATED_NAMES = {"main.fdb_latexmk", "main.synctex.gz"}
SKIP_DIRECTORIES = {".git", ".venv", ".cache", "__pycache__", ".pytest_cache"}


def package_files() -> list[Path]:
    """List release files while ignoring local caches and LaTeX build debris."""
    return sorted(
        (path for path in ROOT.rglob("*")
         if path.is_file()
         and path != MANIFEST
         and not any(part in SKIP_DIRECTORIES for part in path.relative_to(ROOT).parts)
         and path.suffix not in GENERATED_SUFFIXES
         and path.name not in GENERATED_NAMES),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )


def digest(path: Path) -> str:
    """Hash a file in chunks so large raw arrays do not fill memory."""
    hash_value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hash_value.update(chunk)
    return hash_value.hexdigest()


def records() -> list[dict[str, object]]:
    """Record relative paths, lengths, and digests of package files."""
    return [
        {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
         "sha256": digest(path)}
        for path in package_files()
    ]


def main() -> None:
    """Write a new manifest only on request; otherwise verify the existing one."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="record current package files")
    args = parser.parse_args()
    current = records()
    if args.write:
        document = {"package": "PhaseAwareSpectralEntropy", "version": "0.13.1",
                    "file_count": len(current), "files": current}
        MANIFEST.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")
        print(f"Recorded {len(current)} files in {MANIFEST.name}")
        return
    if not MANIFEST.is_file():
        parser.error("PACKAGE_MANIFEST.json is missing; use --write after assembling the package")
    expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if expected["files"] != current or expected["file_count"] != len(current):
        old = {record["path"]: record for record in expected["files"]}
        new = {record["path"]: record for record in current}
        changed = sorted(name for name in old.keys() & new.keys() if old[name] != new[name])
        missing = sorted(old.keys() - new.keys())
        added = sorted(new.keys() - old.keys())
        raise SystemExit(f"Package differs from manifest: changed={changed}, missing={missing}, added={added}")
    print(f"Verified {len(current)} package files and SHA-256 digests")


if __name__ == "__main__":
    main()
