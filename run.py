#!/usr/bin/env python3
"""Convenient entry point for checks and manuscript builds in this release."""

from __future__ import annotations

import argparse
import atexit
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
PAPER = ROOT / "doc_stream_ciphers"
EXPERIMENTS = ROOT / "experiments" / "stream_rounds_study"
AUDITS = (
    "audit_unified_six_results.py",
    "audit_salsa20_transfer.py",
    "audit_matched_nonce_phase.py",
    "audit_same_data_benchmark.py",
    "audit_mask_profiles.py",
)
MPL_CACHE = Path(tempfile.mkdtemp(prefix="phaseaware-mpl-"))
atexit.register(shutil.rmtree, MPL_CACHE, ignore_errors=True)


def run(*args: str, cwd: Path = ROOT) -> None:
    """Run a child command with the local source and study modules importable."""
    environment = os.environ.copy()
    environment.setdefault("MPLCONFIGDIR", str(MPL_CACHE))
    local_paths = os.pathsep.join((str(ROOT / "src"), str(EXPERIMENTS)))
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (local_paths, environment.get("PYTHONPATH", "")) if part
    )
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=cwd, env=environment, check=True)


def main() -> None:
    """Dispatch vectors, archived-data audits, PDF build, or ZIP packaging."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("vectors", "audits", "verify", "build", "package"))
    args = parser.parse_args()
    if args.command in ("vectors", "verify"):
        run(sys.executable, str(ROOT / "tools" / "check_vectors.py"))
    if args.command in ("audits", "verify"):
        for name in AUDITS:
            run(sys.executable, str(EXPERIMENTS / name))
        run(sys.executable, str(ROOT / "tools" / "audit_followups.py"))
    if args.command == "verify":
        run(sys.executable, str(ROOT / "verify_package.py"))
    elif args.command == "build":
        run(sys.executable, str(PAPER / "make_integrated_mask_figure.py"))
        run("latexmk", "-pdf", "-interaction=nonstopmode", "-halt-on-error", "-silent", "main.tex", cwd=PAPER)
    elif args.command == "package":
        run(sys.executable, str(PAPER / "build_submission_package.py"))
        run(sys.executable, str(PAPER / "build_research_release.py"))
        run(sys.executable, str(ROOT / "verify_package.py"), "--write")


if __name__ == "__main__":
    main()
