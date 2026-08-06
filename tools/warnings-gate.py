#!/usr/bin/env python3
"""Run a build command with compiler warnings promoted to errors."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


def deny_warnings_env(base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    existing = env.get("RUSTFLAGS", "").strip()
    # Last lint level wins. Appending keeps caller codegen flags while ensuring
    # an earlier `-A warnings` cannot silently disable the routine gate.
    env["RUSTFLAGS"] = f"{existing} -Dwarnings".strip()
    return env


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="oxide-warnings-gate-") as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text(
            "[package]\nname = \"warnings_gate_control\"\n"
            "version = \"0.0.0\"\nedition = \"2021\"\n\n[workspace]\n",
            encoding="utf-8",
        )
        source = root / "src" / "lib.rs"
        source.write_text(
            "pub fn value() -> u32 { let unused_answer = 42; 7 }\n",
            encoding="utf-8",
        )

        env = dict(os.environ)
        env["RUSTFLAGS"] = "-A warnings"
        red = subprocess.run(
            ["cargo", "check", "--quiet"], cwd=root, env=deny_warnings_env(env),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        expected = (
            "unused variable: `unused_answer`",
            "`-D unused-variables` implied by `-D warnings`",
        )
        if red.returncode == 0 or any(fragment not in red.stderr for fragment in expected):
            print("warnings-gate: self-test FAIL — red control did not fail for unused variable",
                  file=sys.stderr)
            print(red.stderr, file=sys.stderr)
            return 1

        source.write_text("pub fn value() -> u32 { 7 }\n", encoding="utf-8")
        green = subprocess.run(
            ["cargo", "check", "--quiet"], cwd=root, env=deny_warnings_env(),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if green.returncode != 0 or "warning:" in green.stderr:
            print("warnings-gate: self-test FAIL — green control did not pass cleanly",
                  file=sys.stderr)
            print(green.stderr, file=sys.stderr)
            return 1

    print("warnings-gate: self-test PASS — red unused-variable + green clean controls")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if argv[:1] == ["--"]:
        argv = argv[1:]
    if not argv:
        print("usage: warnings-gate.py --self-test | -- COMMAND [ARG ...]", file=sys.stderr)
        return 2
    return subprocess.run(argv, env=deny_warnings_env()).returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
