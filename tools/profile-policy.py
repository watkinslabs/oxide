#!/usr/bin/env python3
"""Gate codegen-profile invariants pinned by docs/07 section 2."""

from pathlib import Path
import re
import sys
import tomllib


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else Path(__file__).resolve().parent.parent
    if len(sys.argv) > 2:
        print("usage: profile-policy.py [repo-root]", file=sys.stderr)
        return 2
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    failures = []
    for name in ("release", "dev"):
        if manifest.get("profile", {}).get(name, {}).get("incremental") is not False:
            failures.append(f"Cargo.toml [profile.{name}] must set incremental = false")

    spec = (root / "docs/07-toolchain-and-targets.md").read_text()
    section = spec.split("## 3 Targets", 1)[0]
    for name in ("release", "dev"):
        pattern = rf"\[profile\.{name}\](?:(?!\[profile\.).)*\bincremental=false\b"
        if not re.search(pattern, section, re.DOTALL):
            failures.append(f"docs/07 section 2 must pin profile.{name} incremental=false")

    if failures:
        for failure in failures:
            print(f"profile-policy: FAIL — {failure}", file=sys.stderr)
        return 1
    print("profile-policy: PASS — release/dev incremental codegen disabled and documented")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
