#!/usr/bin/env python3
"""Print Cargo's canonical target directory for a provided workspace."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    args = parser.parse_args(argv)
    workspace = Path(args.workspace)
    if not workspace.is_absolute():
        workspace = Path.cwd() / workspace
    try:
        workspace = workspace.resolve(strict=True)
    except OSError as error:
        print(f"probe target-directory: workspace unavailable: {error}", file=sys.stderr)
        return 2
    if not workspace.is_dir():
        print(f"probe target-directory: not a directory: {workspace}", file=sys.stderr)
        return 2

    try:
        result = subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            cwd=workspace,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"probe target-directory: cargo metadata failed: {error}", file=sys.stderr)
        return 2
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode or 2
    try:
        metadata = json.loads(result.stdout)
        target = metadata["target_directory"]
    except (KeyError, TypeError, ValueError) as error:
        print(f"probe target-directory: invalid cargo metadata: {error}", file=sys.stderr)
        return 2
    if not isinstance(target, str) or not target:
        print("probe target-directory: metadata target_directory is not a string", file=sys.stderr)
        return 2
    target_path = Path(target)
    if not target_path.is_absolute():
        print("probe target-directory: metadata target_directory is relative", file=sys.stderr)
        return 2
    print(target_path.resolve(strict=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
