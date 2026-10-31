#!/usr/bin/env python3
"""Package and verify the current Electronics submission draft."""

from __future__ import annotations

import hashlib
from pathlib import Path
import zipfile


HERE = Path(__file__).resolve().parent
OUT = HERE / "electronics_iv_diffusion_submission_v0.20.0.zip"
SINGLES = (
    "main.tex", "main.pdf", "biblio.bib",
    "related_work_comparison.tex", "arx_mechanism_compact.tex",
    "publication_unified_mask_followup.pdf",
    "publication_reviewed_spectrum.pdf",
    "COVER_LETTER.md",
)


def main() -> None:
    files = [HERE / name for name in SINGLES]
    files.extend(path for path in (HERE / "Definitions").rglob("*") if path.is_file() and
                 path.suffix in {".cls", ".tex", ".bst", ".eps", ".pdf", ".sty"})
    if not all(path.is_file() for path in files):
        raise FileNotFoundError("Submission package input missing")
    with zipfile.ZipFile(OUT, "w", allowZip64=True) as archive:
        for path in sorted(files, key=lambda item: item.relative_to(HERE).as_posix()):
            relative = path.relative_to(HERE).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(2026, 10, 31, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())
    with zipfile.ZipFile(OUT) as archive:
        if archive.testzip() is not None:
            raise AssertionError("Submission ZIP CRC failure")
        expected = {path.relative_to(HERE).as_posix() for path in files}
        if set(archive.namelist()) != expected:
            raise AssertionError("Submission ZIP members differ from allowlist")
        for path in files:
            name = path.relative_to(HERE).as_posix()
            if hashlib.sha256(archive.read(name)).digest() != hashlib.sha256(path.read_bytes()).digest():
                raise AssertionError(f"Submission ZIP hash mismatch: {name}")
    print(f"Verified {len(files)} submission files in {OUT.name}")
    print("SHA-256:", hashlib.sha256(OUT.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
