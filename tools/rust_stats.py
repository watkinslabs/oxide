#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import tomllib


@dataclass
class FileStats:
    lines: int = 0
    code: int = 0
    comments: int = 0
    blanks: int = 0

    def add(self, other: "FileStats") -> None:
        self.lines += other.lines
        self.code += other.code
        self.comments += other.comments
        self.blanks += other.blanks

    @property
    def files(self) -> int:
        return 0


@dataclass
class BucketStats(FileStats):
    rust_files: int = 0

    def add_file(self, file_stats: FileStats) -> None:
        self.rust_files += 1
        self.add(file_stats)


def classify_rust_lines(text: str) -> FileStats:
    stats = FileStats()
    in_block = 0

    for raw in text.splitlines():
        stats.lines += 1
        line = raw.rstrip("\n")
        if not line.strip():
            stats.blanks += 1
            continue

        i = 0
        has_code = False
        has_comment = False

        while i < len(line):
            if in_block:
                has_comment = True
                end = line.find("*/", i)
                if end == -1:
                    i = len(line)
                    break
                in_block -= 1
                i = end + 2
                continue

            if line.startswith("//", i):
                has_comment = True
                break

            if line.startswith("/*", i):
                has_comment = True
                in_block += 1
                i += 2
                continue

            if not line[i].isspace():
                has_code = True
            i += 1

        if has_code:
            stats.code += 1
        elif has_comment:
            stats.comments += 1
        else:
            stats.blanks += 1

    return stats


def read_workspace_members(root: Path) -> List[Path]:
    cargo_toml = root / "Cargo.toml"
    if not cargo_toml.exists():
        return []
    data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    workspace = data.get("workspace", {})
    members = workspace.get("members", [])
    out: List[Path] = []
    for member in members:
        matched = sorted(root.glob(member))
        if not matched:
            out.append((root / member).resolve())
        else:
            out.extend(path.resolve() for path in matched)
    return out


def all_rust_files(root: Path) -> Iterable[Path]:
    ignore_dirs = {
        ".git",
        "target",
        ".idea",
        ".vscode",
        "__pycache__",
    }
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs]
        for name in filenames:
            if name.endswith(".rs"):
                yield Path(dirpath) / name


def top_level_area(root: Path, file_path: Path) -> str:
    rel = file_path.relative_to(root)
    return rel.parts[0] if rel.parts else "."


def find_owner_member(root: Path, members: List[Path], file_path: Path) -> str:
    rel = file_path.relative_to(root)
    best_name = "unowned"
    best_len = -1
    for member in members:
        try:
            member_rel = member.relative_to(root)
        except ValueError:
            continue
        parts = member_rel.parts
        if len(parts) > best_len and rel.parts[: len(parts)] == parts:
            best_len = len(parts)
            best_name = member_rel.as_posix()
    return best_name


def count_repo(root: Path) -> Tuple[BucketStats, Dict[str, BucketStats], Dict[str, BucketStats], List[Tuple[str, int]]]:
    workspace_members = read_workspace_members(root)
    total = BucketStats()
    by_area: Dict[str, BucketStats] = {}
    by_member: Dict[str, BucketStats] = {}
    by_file_lines: List[Tuple[str, int]] = []

    for rust_file in all_rust_files(root):
        text = rust_file.read_text(encoding="utf-8")
        fstats = classify_rust_lines(text)
        total.add_file(fstats)

        area_name = top_level_area(root, rust_file)
        area = by_area.setdefault(area_name, BucketStats())
        area.add_file(fstats)

        member_name = find_owner_member(root, workspace_members, rust_file)
        member = by_member.setdefault(member_name, BucketStats())
        member.add_file(fstats)

        by_file_lines.append((rust_file.relative_to(root).as_posix(), fstats.lines))

    by_file_lines.sort(key=lambda p: p[1], reverse=True)
    return total, by_area, by_member, by_file_lines


def format_table(title: str, rows: List[Tuple[str, BucketStats]], limit: int) -> str:
    rows = rows[:limit]
    name_w = max(len(title), *(len(name) for name, _ in rows), 4)
    out = []
    out.append(f"{title:<{name_w}}  files  lines   code  cmt  blank")
    out.append(f"{'-' * name_w}  -----  -----  -----  ---  -----")
    for name, s in rows:
        out.append(
            f"{name:<{name_w}}  {s.rust_files:>5}  {s.lines:>5}  {s.code:>5}  {s.comments:>3}  {s.blanks:>5}"
        )
    return "\n".join(out)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Count Rust lines and show repo stats by area and workspace crate."
    )
    p.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root (default: current directory)",
    )
    p.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of rows shown for each leaderboard (default: 10)",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Print JSON output instead of text tables",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    total, by_area, by_member, by_file = count_repo(root)

    top_areas = sorted(by_area.items(), key=lambda kv: kv[1].lines, reverse=True)
    top_members = sorted(
        by_member.items(),
        key=lambda kv: (kv[0] == "unowned", -kv[1].lines),
    )
    top_files = by_file[: args.top]

    if args.json:
        payload = {
            "root": root.as_posix(),
            "total": {
                "rust_files": total.rust_files,
                "lines": total.lines,
                "code": total.code,
                "comments": total.comments,
                "blanks": total.blanks,
            },
            "by_area": [
                {
                    "area": name,
                    "rust_files": s.rust_files,
                    "lines": s.lines,
                    "code": s.code,
                    "comments": s.comments,
                    "blanks": s.blanks,
                }
                for name, s in top_areas
            ],
            "by_workspace_member": [
                {
                    "member": name,
                    "rust_files": s.rust_files,
                    "lines": s.lines,
                    "code": s.code,
                    "comments": s.comments,
                    "blanks": s.blanks,
                }
                for name, s in top_members
            ],
            "largest_files": [
                {"path": path, "lines": lines}
                for path, lines in top_files
            ],
        }
        print(json.dumps(payload, indent=2))
        return 0

    print(f"Repo: {root}")
    print(
        f"Rust files: {total.rust_files} | lines: {total.lines} | code: {total.code} | comments: {total.comments} | blanks: {total.blanks}"
    )
    print()
    print(format_table("area", top_areas, args.top))
    print()
    print(format_table("workspace-member", top_members, args.top))
    print()
    if top_files:
        path_w = max(8, *(len(p) for p, _ in top_files))
        print(f"{'largest':<{path_w}}  lines")
        print(f"{'-' * path_w}  -----")
        for path, lines in top_files:
            print(f"{path:<{path_w}}  {lines:>5}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
