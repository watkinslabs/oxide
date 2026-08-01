#!/usr/bin/env python3
"""Kernel stack-frame size gate — Linux `CONFIG_FRAME_WARN` (`skizm.md` Step 6).

A single function that reserves a large stack frame is how a kernel stack
overflows. This tree has already paid for that once: C213 traced a
long-running heap corruption to a kernel-stack overflow past a 16 KiB stack
into the adjacent heap block, and the fix needed guard pages to even see it.
A frame that big is visible in the binary at build time; this reads it out.

Why disassembly rather than `-Z emit-stack-sizes`: the kernel is built with
`-Zbuild-std`, and adding an unstable codegen flag to that build changes what
gets compiled and how it is cached. The prologue is unambiguous and needs no
build change, so the gate can run on any kernel ELF that already exists.

Frames larger than a page are emitted by LLVM as a sequence of probed
`sub`s (stack clash protection), so per-function reservations are SUMMED
rather than maxed — otherwise a 32 KiB frame reads as 4096.

Linux's `CONFIG_FRAME_WARN` warns rather than fails, and this keeps that
shape: `--warn` reports, `--fail` is the never-exceed ceiling that breaks the
build. One frame taking half the kernel stack is indefensible regardless of
what the rest of the call chain does.

The baseline is keyed on the DEMANGLED path, for the reason spelled out in
`rust_symbol_identity`: a mangled name carries a crate disambiguator that
changes with the features the crate was built with, so a baseline keyed on it
makes the verdict depend on which build produced the ELF. An entry naming a
frame that is not in the ELF is reported as STALE rather than ignored — it is
dead permission, and it needs the opposite fix from a new over-ceiling frame.
"""

import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rust_symbol_identity as rsi        # noqa: E402

# The two disassemblers print the SAME instruction differently, and the gate is
# useless — silently passing — if it only understands one:
#   GNU objdump : `sub    $0x1000,%rsp`
#   llvm-objdump: `subq   $0x1000, %rsp`      (size suffix, space after comma)
# Both forms are accepted deliberately; a regex that matched only GNU's made the
# tool report zero large frames on a binary that has nine.
X86_SUB = re.compile(r"\ssub[qlwb]?\s+\$0x([0-9a-f]+),\s*%rsp\b")
# aarch64: `sub sp, sp, #0x1234` / `#1234`, either disassembler.
ARM_SUB = re.compile(r"\ssub\s+sp,\s*sp,\s*#(?:0x([0-9a-f]+)|(\d+))")
# aarch64 pre-index push that also opens the frame: `stp x29, x30, [sp, #-0x20]!`
ARM_STP = re.compile(r"\sstp\s+.*\[sp,\s*#-(?:0x([0-9a-f]+)|(\d+))\]!")
FUNC = re.compile(r"^\s*[0-9a-f]+\s*<(.+)>:")


def parse(objdump_out):
    """-> {function: reserved_bytes}. Sums every reservation in the body."""
    frames, fn, cur = {}, None, 0
    for line in objdump_out.splitlines():
        m = FUNC.match(line)
        if m:
            if fn is not None:
                frames[fn] = cur
            fn, cur = m.group(1), 0
            continue
        if fn is None:
            continue
        for rx in (X86_SUB, ARM_SUB, ARM_STP):
            m = rx.search(line)
            if m:
                hexv = m.group(1)
                if hexv is not None:
                    cur += int(hexv, 16)
                elif m.lastindex and m.group(m.lastindex):
                    cur += int(m.group(m.lastindex))
                break
    if fn is not None:
        frames[fn] = cur
    return frames


def demangle(names):
    """-> readable names, via the same identity function the baseline uses.

    No external demangler: a gate whose output depends on whether `rustfilt`
    happens to be installed is one more way for it to disagree with itself.
    """
    return [rsi.identity(n) for n in names]


SELF_TEST_INPUT = """
0000000000201000 <small_x86>:
  201000: push   %rbp
  201004: sub    $0x40,%rsp
  201008: ret

0000000000202000 <probed_x86>:
  202000: sub    $0x1000,%rsp
  202004: orq    $0x0,(%rsp)
  202008: sub    $0x1000,%rsp
  20200c: orq    $0x0,(%rsp)
  202010: sub    $0x28,%rsp
  202014: ret

0000000000203000 <arm_frame>:
  203000: stp     x29, x30, [sp, #-0x20]!
  203004: sub     sp, sp, #0x400
  203008: ret

0000000000204000 <leaf>:
  204000: ret

0000000000205000 <llvm_syntax_x86>:
  205000: subq   $0x800, %rsp
  205008: retq
"""


def self_test():
    got = parse(SELF_TEST_INPUT)
    want = {
        # one plain reservation
        "small_x86": 0x40,
        # probe-split frame: MUST sum, or an 8 KiB frame reads as 4096 and the
        # gate silently misses exactly the case it exists to catch.
        "probed_x86": 0x1000 + 0x1000 + 0x28,
        # aarch64 opens the frame with a pre-index stp, then extends it
        "arm_frame": 0x20 + 0x400,
        # a leaf that touches no stack must not be reported at all
        "leaf": 0,
        # llvm-objdump spelling: size suffix and a space after the comma. A
        # regex tuned to GNU objdump alone silently reports 0 here, which made
        # the whole gate pass on a binary with nine over-ceiling frames.
        "llvm_syntax_x86": 0x800,
    }
    bad = [(k, got.get(k), v) for k, v in want.items() if got.get(k) != v]
    for k, g, w in bad:
        print(f"self-test FAIL {k}: got {g}, want {w}", file=sys.stderr)
    if set(got) != set(want):
        print(f"self-test FAIL: functions {sorted(got)} != {sorted(want)}", file=sys.stderr)
        return 1
    if bad:
        return 1
    rsi.self_test()
    # The baseline must not care which build produced the ELF: two builds of
    # one tree differ in the crate disambiguator and in nothing else.
    a = "_RNvNtNtCseQ963CMHBD6_5kmain5kmain5entry11kernel_main"
    b = "_RNvNtNtCs1Yf3GkQE07G_5kmain5kmain5entry11kernel_main"
    assert a != b and rsi.identity(a) == rsi.identity(b)
    print(f"frame-size-gate: self-test PASS ({len(want)} cases + baseline identity)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf", nargs="?")
    ap.add_argument("--self-test", action="store_true",
                    help="check the prologue parser against synthetic disassembly and exit")
    ap.add_argument("--warn", type=int, default=2048,
                    help="report frames at or above this (Linux CONFIG_FRAME_WARN, 64-bit default 2048)")
    ap.add_argument("--fail", type=int, default=8192,
                    help="hard ceiling: any frame at or above this fails the build")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--allow-stale", action="store_true",
                    help="report baseline entries whose frame is not in this ELF instead "
                         "of failing on them (they are dead permission either way)")
    ap.add_argument("--baseline",
                    help="file of `bytes<TAB>demangled path` for frames already over the "
                         "ceiling. "
                         "Those are tolerated at or below their recorded size, so the gate "
                         "fails on NEW or WORSENED frames while the known set is burned down.")
    ap.add_argument("--write-baseline", action="store_true",
                    help="rewrite --baseline from this ELF instead of checking against it")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.elf:
        ap.error("an ELF path is required unless --self-test is given")

    # llvm-objdump first: it is multi-arch, so one host binary reads both the
    # x86_64 and aarch64 kernels. GNU objdump is usually built for the host
    # arch only and simply refuses the foreign ELF.
    out, last = None, None
    for tool in ("llvm-objdump", "objdump"):
        try:
            out = subprocess.run([tool, "-d", "--no-show-raw-insn", args.elf],
                                 capture_output=True, text=True, check=True).stdout
            break
        except FileNotFoundError:
            last = f"{tool} not found"
        except subprocess.CalledProcessError as e:
            last = f"{tool} failed: {e.stderr.strip() or e}"
    if out is None:
        print(f"frame-size-gate: could not disassemble {args.elf} ({last})", file=sys.stderr)
        return 2

    frames = parse(out)
    if not frames:
        print(f"frame-size-gate: no functions found in {args.elf} — wrong file?", file=sys.stderr)
        return 2

    ranked = sorted(frames.items(), key=lambda kv: -kv[1])
    over_warn = [(n, s) for n, s in ranked if s >= args.warn]
    over_fail = [(n, s) for n, s in ranked if s >= args.fail]

    # Identity, not the mangled symbol. Many-to-one is possible (one generic
    # instantiated in two crates, an LLVM clone beside its original), so a
    # baseline entry covers the LARGEST frame sharing that identity.
    ident = {raw: rsi.identity(raw) for raw in frames}
    present = set(ident.values())
    by_id, by_id_raw = {}, {}
    for n, sz in over_fail:
        k = ident[n]
        if sz > by_id.get(k, -1):
            by_id[k], by_id_raw[k] = sz, n

    if args.write_baseline:
        if not args.baseline:
            print("frame-size-gate: --write-baseline needs --baseline", file=sys.stderr)
            return 2
        with open(args.baseline, "w") as f:
            f.write("# Frames already over the hard ceiling when the gate was introduced.\n")
            f.write("# Tolerated at or below the recorded size ONLY; a new or worsened frame\n")
            f.write("# fails. Burn this list down — do not add to it.\n")
            for k, sz in sorted(by_id.items(), key=lambda kv: -kv[1]):
                f.write(f"{sz}\t{k}\n")
        print(f"frame-size-gate: wrote {len(over_fail)} baseline entries to {args.baseline}")
        return 0

    baseline = {}
    if args.baseline:
        try:
            for line in open(args.baseline):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                sz, name = line.split("\t", 1)
                baseline[rsi.identity(name.strip())] = int(sz)
        except FileNotFoundError:
            print(f"frame-size-gate: baseline {args.baseline} not found", file=sys.stderr)
            return 2

    fresh = [(k, sz) for k, sz in by_id.items() if k not in baseline]
    worse = [(k, sz, baseline[k]) for k, sz in by_id.items()
             if k in baseline and sz > baseline[k]]
    stale = [k for k in baseline if k not in present]
    regressions = fresh + worse

    print(f"frame-size-gate: {args.elf}")
    print(f"  functions scanned : {len(frames)}")
    print(f"  >= warn ({args.warn:5d}B): {len(over_warn)}")
    print(f"  >= fail ({args.fail:5d}B): {len(over_fail)}")
    if over_warn:
        shown = over_warn[: args.top]
        names = demangle([n for n, _ in shown])
        print(f"  largest {len(shown)}:")
        for (_, size), pretty in zip(shown, names):
            print(f"    {size:7d}  {pretty}")

    if baseline:
        print(f"  baselined       : {len(by_id) - len(regressions)} of {len(by_id)} over-ceiling frames")

    # A NEW/WORSENED frame is code to fix; a STALE entry is a line to delete.
    if regressions:
        print(f"\nframe-size-gate: FAIL — {len(regressions)} function(s) reserve "
              f">= {args.fail} B of stack and are new or worse than the baseline:",
              file=sys.stderr)
        for k, size in sorted(fresh, key=lambda t: -t[1]):
            print(f"    {size:7d}  NEW       {k}", file=sys.stderr)
            print(f"             (symbol {by_id_raw[k]})", file=sys.stderr)
        for k, size, was in sorted(worse, key=lambda t: -t[1]):
            print(f"    {size:7d}  WORSENED  {k}  (baseline {was}, +{size - was})", file=sys.stderr)
            print(f"             (symbol {by_id_raw[k]})", file=sys.stderr)
        print("\nA frame this large overflows the kernel stack on a deep call chain; "
              "split the function or move the buffer off-stack.", file=sys.stderr)
    if stale and not args.allow_stale:
        print(f"\nframe-size-gate: FAIL — {len(stale)} baseline entr(y/ies) name a frame "
              f"that is not in {args.elf} at all:", file=sys.stderr)
        for k in sorted(stale):
            print(f"    STALE  {k}", file=sys.stderr)
        print("\nDelete those lines: the function is gone, and a baseline that keeps "
              "permission for code that no longer exists stops meaning anything.",
              file=sys.stderr)
    if regressions or (stale and not args.allow_stale):
        return 1
    if stale:
        print(f"  stale (ignored) : {len(stale)} entr(y/ies) name a frame not in this ELF")
    print("frame-size-gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
