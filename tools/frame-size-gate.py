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
"""

import argparse
import re
import subprocess
import sys

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
    """Best-effort rustfilt/c++filt; falls back to the raw symbol."""
    try:
        p = subprocess.run(["rustfilt"], input="\n".join(names),
                           capture_output=True, text=True, check=True)
        return p.stdout.splitlines()
    except Exception:
        return names


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
    print(f"frame-size-gate: self-test PASS ({len(want)} cases)")
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
    ap.add_argument("--baseline",
                    help="file of `bytes<TAB>symbol` for frames already over the ceiling. "
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

    if args.write_baseline:
        if not args.baseline:
            print("frame-size-gate: --write-baseline needs --baseline", file=sys.stderr)
            return 2
        with open(args.baseline, "w") as f:
            f.write("# Frames already over the hard ceiling when the gate was introduced.\n")
            f.write("# Tolerated at or below the recorded size ONLY; a new or worsened frame\n")
            f.write("# fails. Burn this list down — do not add to it.\n")
            for n, sz in sorted(over_fail, key=lambda kv: -kv[1]):
                f.write(f"{sz}\t{n}\n")
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
                baseline[name] = int(sz)
        except FileNotFoundError:
            print(f"frame-size-gate: baseline {args.baseline} not found", file=sys.stderr)
            return 2

    regressions = [(n, s) for n, s in over_fail
                   if n not in baseline or s > baseline[n]]

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
        print(f"  baselined       : {len(over_fail) - len(regressions)} of {len(over_fail)} over-ceiling frames")

    if regressions:
        print(f"\nframe-size-gate: FAIL — {len(regressions)} function(s) reserve "
              f">= {args.fail} B of stack and are new or worse than the baseline:",
              file=sys.stderr)
        for name, size in regressions:
            was = baseline.get(name)
            note = f" (baseline {was})" if was is not None else " (new)"
            print(f"    {size:7d}{note}  {name}", file=sys.stderr)
        print("\nA frame this large overflows the kernel stack on a deep call chain; "
              "split the function or move the buffer off-stack.", file=sys.stderr)
        return 1
    print("frame-size-gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
