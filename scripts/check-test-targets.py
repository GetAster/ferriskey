#!/usr/bin/env python3
"""Fail when a workspace member has more test, bench or example targets than
its repository allows.

Each such target is a separately linked program, so every extra one relinks
the whole dependency graph on each change. Defaults: one test target, no
benches, no examples. The allowlist raises a package's limit:

    # package kind max
    portal-cas test 31
    portal-embed example 3

Counts in the allowlist may only be lowered. Reads `cargo metadata --no-deps`,
so it builds nothing. Copy this file into a repository rather than calling it
from ~/dev/ai, so the repository's hooks and CI keep working elsewhere.

Usage: check-test-targets.py [ALLOWLIST]   (default scripts/test-targets.allow)
"""

import collections
import json
import pathlib
import subprocess
import sys

DEFAULTS = {"test": 1, "bench": 0, "example": 0}


def main() -> int:
    allow_path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "scripts/test-targets.allow")
    limits = {}
    if allow_path.exists():
        for n, line in enumerate(allow_path.read_text().splitlines(), 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                package, kind, count = line.split()
                if kind not in DEFAULTS:
                    raise ValueError(kind)
                limits[(package, kind)] = int(count)
            except ValueError:
                print(f"check-test-targets: {allow_path}:{n}: expected 'package test|bench|example max'", file=sys.stderr)
                return 2

    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        check=True, capture_output=True, text=True).stdout)
    counts = collections.Counter()
    for package in meta["packages"]:
        for target in package["targets"]:
            for kind in target["kind"]:
                if kind in DEFAULTS:
                    counts[(package["name"], kind)] += 1

    failures = [
        f"{package} has {count} {kind} targets, allowed {limits.get((package, kind), DEFAULTS[kind])}"
        for (package, kind), count in sorted(counts.items())
        if count > limits.get((package, kind), DEFAULTS[kind])
    ]
    for failure in failures:
        print(f"check-test-targets: {failure}.", file=sys.stderr)
    if failures:
        print("check-test-targets: each target is a separately linked program. Add tests as modules\n"
              "check-test-targets: of the crate's existing test binary (tests/it/main.rs) or as unit\n"
              f"check-test-targets: tests in src/. Limits are in {allow_path}; they may only fall.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
