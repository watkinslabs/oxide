#!/usr/bin/env python3
"""Require every faultable user cmpxchg instruction to have an ELF fixup."""

import argparse
import pathlib
import re
import struct
import subprocess
import tempfile

SYMBOL = "oxide_raw_cmpxchg_user_u32"


def output(*args: str) -> str:
    return subprocess.check_output(args, text=True)


def symbol_range(elf: pathlib.Path) -> tuple[int, int]:
    for line in output("llvm-readelf", "-sW", str(elf)).splitlines():
        fields = line.split()
        if fields and fields[-1] == SYMBOL and len(fields) >= 8:
            start = int(fields[1], 16)
            return start, start + int(fields[2])
    raise SystemExit(f"uaccess-extable-gate: missing symbol {SYMBOL}: {elf}")


def section_addr(elf: pathlib.Path) -> int:
    pattern = re.compile(r"^\s*\[\s*\d+\]\s+\.ex_table\s+\S+\s+([0-9a-fA-F]+)\s")
    for line in output("llvm-readelf", "-SW", str(elf)).splitlines():
        match = pattern.match(line)
        if match:
            return int(match.group(1), 16)
    raise SystemExit(f"uaccess-extable-gate: missing .ex_table: {elf}")


def count_fixups(elf: pathlib.Path) -> int:
    start, end = symbol_range(elf)
    base = section_addr(elf)
    with tempfile.TemporaryDirectory(prefix="oxide-uaccess-extable-") as tmp:
        raw = pathlib.Path(tmp) / "extable.bin"
        subprocess.check_call(["llvm-objcopy", f"--dump-section=.ex_table={raw}", str(elf)])
        data = raw.read_bytes()
    if len(data) % 8:
        raise SystemExit(f"uaccess-extable-gate: malformed .ex_table size {len(data)}: {elf}")
    found = 0
    for off in range(0, len(data), 8):
        insn_rel, fixup_rel = struct.unpack_from("<ii", data, off)
        insn = base + off + insn_rel
        fixup = base + off + 4 + fixup_rel
        if start <= insn < end:
            if not start <= fixup < end:
                raise SystemExit(
                    f"uaccess-extable-gate: {SYMBOL} fixup escapes symbol: {fixup:#x}: {elf}"
                )
            found += 1
    return found


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=pathlib.Path)
    parser.add_argument("--expected", type=int, required=True)
    args = parser.parse_args()
    found = count_fixups(args.elf)
    if found != args.expected:
        raise SystemExit(
            f"uaccess-extable-gate: {SYMBOL} has {found} fixup(s), expected {args.expected}: {args.elf}"
        )
    print(f"uaccess-extable-gate: PASS {args.elf} ({found} fixup(s))")


if __name__ == "__main__":
    main()
