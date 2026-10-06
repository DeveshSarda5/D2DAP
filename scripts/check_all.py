"""Run every static check and the test suite (cross-platform replacement for a Makefile).

Usage::

    python scripts/check_all.py          # format check, lint, type check, tests
    python scripts/check_all.py --fast   # skip tests marked slow
"""

from __future__ import annotations

import argparse
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fast", action="store_true", help="skip slow tests")
    args = parser.parse_args()

    py = sys.executable
    pytest_cmd = [py, "-m", "pytest", "-q"]
    if args.fast:
        pytest_cmd += ["-m", "not slow"]
    steps: list[tuple[str, list[str]]] = [
        ("format", [py, "-m", "ruff", "format", "--check", "backend", "scripts"]),
        ("lint", [py, "-m", "ruff", "check", "backend", "scripts"]),
        ("types", [py, "-m", "mypy"]),
        ("tests", pytest_cmd),
    ]
    failed: list[str] = []
    for name, cmd in steps:
        print(f"\n=== {name}: {' '.join(cmd[2:])}", flush=True)
        if subprocess.run(cmd, check=False).returncode != 0:  # noqa: S603 - fixed argv
            failed.append(name)
    print("\nFAILED: " + ", ".join(failed) if failed else "\nALL CHECKS PASSED")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
