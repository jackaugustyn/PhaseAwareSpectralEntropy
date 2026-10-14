#!/usr/bin/env python3
"""Run the publication's self-contained cipher-vector and invariant checks.

The test functions take no fixtures, so this runner needs only the packages in
``requirements.txt``. It reports the failing function and propagates errors.
"""

from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "experiments" / "stream_rounds_study"))


def load_module(path: Path):
    """Load one vector-check file without requiring a pytest installation."""
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    """Run all zero-argument ``test_*`` functions and print a short summary."""
    count = 0
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        module = load_module(path)
        for name, function in inspect.getmembers(module, inspect.isfunction):
            if not name.startswith("test_") or function.__module__ != module.__name__:
                continue
            if inspect.signature(function).parameters:
                raise TypeError(f"Check requires arguments: {path.name}:{name}")
            function()
            count += 1
            print(f"PASS {path.name}:{name}")
    if count == 0:
        raise RuntimeError("No vector checks were discovered")
    print(f"Passed {count} vector and invariant checks")


if __name__ == "__main__":
    main()
