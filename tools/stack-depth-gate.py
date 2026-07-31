#!/usr/bin/env python3
"""Kernel stack-DEPTH gate — worst-case bytes along a static call path.

Sibling of `frame-size-gate.py`, and deliberately not a replacement. That tool
answers "is any single function's frame too big" (Linux `CONFIG_FRAME_WARN`).
This one answers "how much stack does the deepest call chain reaching this
function consume", which is the question a stack overflow actually asks.

The two are not interchangeable. The virtio child-probe overflow that motivated
this tool was `Driver::probe` (8448 B) calling `begin_session` (6064 B): 14512 B
of a 16 KiB stack, with neither frame anywhere near the 8192 B per-function
ceiling. The per-function gate passed on that binary. Reached from a `sysfs`
bind write already ~1.6 KiB deep, the console sink was entered with 224 bytes of
headroom and the next push hit the guard page — a `#DF` on x86_64 and a
`[BADSTACK]` on aarch64, both diagnosed only after the kernel died.

Everything here is readable out of an already-linked kernel ELF, so this needs
no rebuild, no `-Z emit-stack-sizes`, and no change to how `-Zbuild-std`
compiles the tree.

WHAT THIS CANNOT SEE (read this before trusting a number)
---------------------------------------------------------
It is a STATIC walker over direct call edges. It is a lower bound, never a
proof:

  * INDIRECT CALLS (`call *%rax`, `blr x8`) are invisible. Every `dyn`-free
    trait object this kernel avoids is one thing, but `FileOps`, `Driver`, the
    klog sinks and the softirq handlers are all called through function
    pointers, and the walker cannot follow them. Any function whose path
    crosses one is reported `+indirect`, and its true depth is UNKNOWN and
    larger than printed.
  * RECURSION makes the longest path unbounded. A cycle is reported as
    `recursive` and contributes its own frame once rather than silently
    truncating to zero, which is what a naive memoized DFS does.
  * INTERRUPTS AND EXCEPTION ENTRY are not modelled. A trap arriving mid-path
    adds its own frame on top of whatever is printed.
  * Only the prologue reservation is counted. A dynamic `alloca` or a
    variable-length stack array does not appear.

So a PASS means "no over-threshold path among the edges the linker made
visible", not "cannot overflow". A FAIL is always real.

ACCOUNTING
----------
x86_64: the caller's `CALL` pushes the return address, so a callee's cost is
8 + prologue pushes + prologue `sub $N,%rsp`.
aarch64: the frame-opening `stp x29, x30, [sp, #-N]!` already carries the link
register, so the reservation is the whole cost and nothing is added.

Reservations are SUMMED across the prologue: a frame larger than a page is
emitted as a sequence of probed `sub`s (stack-clash protection) with a store
between them, so taking the max reads an 8 KiB frame as 4096.
"""

import argparse
import re
import subprocess
import sys

# Both disassemblers must be understood or the gate silently passes:
#   GNU objdump : `sub    $0x1000,%rsp`      `call   ffffffff80001000 <foo>`
#   llvm-objdump: `subq   $0x1000, %rsp`     `callq  0xffffffff80001000 <foo>`
FUNC = re.compile(r"^\s*[0-9a-f]+\s*<(.+)>:")
INSN = re.compile(r"^\s*[0-9a-f]+:\s+(\S+)\s*(.*)$")

X86_SUB = re.compile(r"^\$0x([0-9a-f]+),\s*%rsp\b")
X86_CALL_DIRECT = re.compile(r"<([^>+]+)(?:\+0x[0-9a-f]+)?>")
ARM_SUB = re.compile(r"^sp,\s*sp,\s*#(?:0x([0-9a-f]+)|(\d+))")
ARM_PUSH = re.compile(r"\[sp,\s*#-(?:0x([0-9a-f]+)|(\d+))\]!")

# Instructions that end the prologue window. A probed reservation interleaves
# stores (`movq $0,(%rsp)` / `orq $0,(%rsp)` / `str xzr,[sp]`) between its subs,
# and those must NOT close the window or the sum stops at the first page.
X86_PROLOGUE_END = ("call", "callq", "j", "ret", "retq")
ARM_PROLOGUE_END = ("bl", "blr", "b", "br", "ret", "cb", "tb")


# Edges into the abort family are pruned by default. Every kernel profile is
# `panic = "abort"` (`07§5`), so these never return: the kernel is already
# dying and its remaining stack is not a budget anyone is spending. Keeping
# them costs more than the ~600 B they add — the panic formatter calls back
# into the klog sink, which closes a cycle that marks two thirds of the call
# graph "recursive", and the deepest branch out of almost every function
# becomes its bounds-check rather than its real work. `--include-fatal` keeps
# them for anyone auditing what an oops itself costs.
def is_fatal(sym):
    return (
        "9panicking" in sym                      # core::panicking::*
        or "core::panicking" in sym
        or "rust_begin_unwind" in sym
        or "handle_alloc_error" in sym
        or "alloc_error_handler" in sym
        or "unwrap_failed" in sym
        or "expect_failed" in sym
        or sym.endswith("_fail")
        or "16slice_index_fail" in sym
        or "slice_end_index" in sym
        or "slice_start_index" in sym
    )


def _imm(m):
    """Hex group 1 or decimal group 2 from the immediate regexes."""
    return int(m.group(1), 16) if m.group(1) is not None else int(m.group(2))


def parse(text, arch, include_fatal=False):
    """-> (frames, calls, indirect)

    frames[f]   entry cost of f in bytes (see ACCOUNTING)
    calls[f]    set of directly-called symbols
    indirect[f] count of unresolved indirect call sites in f
    """
    frames, calls, indirect = {}, {}, {}
    fn, prologue = None, False
    for line in text.splitlines():
        m = FUNC.match(line)
        if m:
            fn = m.group(1)
            # x86_64 pays 8 for the return address the CALL pushed; on aarch64
            # the link register lives inside the callee's own reservation.
            frames[fn] = 8 if arch == "x86_64" else 0
            calls[fn], indirect[fn], prologue = set(), 0, True
            continue
        if fn is None:
            continue
        m = INSN.match(line)
        if not m:
            continue
        op, args = m.group(1), m.group(2).strip()

        if arch == "x86_64":
            if prologue:
                if op.startswith("push"):
                    frames[fn] += 8
                    continue
                if op.startswith("sub"):
                    sub = X86_SUB.match(args)
                    if sub:
                        frames[fn] += int(sub.group(1), 16)
                        continue
                if op.startswith(X86_PROLOGUE_END):
                    prologue = False
            if op.startswith(("call", "callq")):
                if args.startswith("*") or args.startswith("%"):
                    indirect[fn] += 1
                else:
                    t = X86_CALL_DIRECT.search(args)
                    if t:
                        if include_fatal or not is_fatal(t.group(1)):
                            calls[fn].add(t.group(1))
                    else:
                        indirect[fn] += 1
        else:
            if prologue:
                if op in ("stp", "str"):
                    push = ARM_PUSH.search(args)
                    if push:
                        frames[fn] += _imm(push)
                        continue
                if op == "sub":
                    sub = ARM_SUB.match(args)
                    if sub:
                        frames[fn] += _imm(sub)
                        continue
                if op.startswith(ARM_PROLOGUE_END):
                    prologue = False
            if op == "bl":
                t = X86_CALL_DIRECT.search(args)
                if t:
                    if include_fatal or not is_fatal(t.group(1)):
                        calls[fn].add(t.group(1))
                else:
                    indirect[fn] += 1
            elif op in ("blr", "br"):
                indirect[fn] += 1
    return frames, calls, indirect


class Walker:
    """Longest static call path, with recursion and indirect calls surfaced.

    Iterative rather than recursive: the kernel's call graph is deeper than
    CPython's default limit, and a `RecursionError` inside a stack-depth tool
    would be its own joke.
    """

    def __init__(self, frames, calls, indirect):
        self.frames, self.calls, self.indirect = frames, calls, indirect
        self.depth, self.next_hop = {}, {}
        self.recursive, self.crosses_indirect = set(), set()

    def walk(self, root):
        WHITE, GREY = 0, 1
        color = {}
        stack = [(root, False)]
        while stack:
            fn, revisit = stack.pop()
            if revisit:
                best, hop, rec, ind = 0, None, False, self.indirect.get(fn, 0) > 0
                # Sorted, not set order: which back edge a cycle gets cut at
                # decides the reported depth, and Python's per-process string
                # hashing would otherwise make the same ELF measure differently
                # run to run — a flaky gate is a disabled gate.
                for callee in sorted(self.calls.get(fn, ())):
                    if callee not in self.frames:
                        continue
                    if color.get(callee) == GREY:
                        # Back edge: fn participates in a cycle. Counting the
                        # cycle once and flagging it beats pretending it is 0.
                        rec = True
                        continue
                    d = self.depth.get(callee, 0)
                    if callee in self.recursive:
                        rec = True
                    if callee in self.crosses_indirect:
                        ind = True
                    if d > best:
                        best, hop = d, callee
                self.depth[fn] = self.frames.get(fn, 0) + best
                self.next_hop[fn] = hop
                if rec:
                    self.recursive.add(fn)
                if ind:
                    self.crosses_indirect.add(fn)
                color[fn] = 2
                continue
            if fn in self.depth:
                continue
            if color.get(fn) == GREY:
                continue
            color[fn] = GREY
            stack.append((fn, True))
            for callee in sorted(self.calls.get(fn, ()), reverse=True):
                if callee in self.frames and callee not in self.depth and color.get(callee) != GREY:
                    stack.append((callee, False))
        return self.depth.get(root, 0)

    def walk_all(self):
        for fn in sorted(self.frames):
            if fn not in self.depth:
                self.walk(fn)
        return self.depth

    def path(self, root, limit=24):
        out, fn = [], root
        while fn is not None and len(out) < limit:
            out.append(fn)
            fn = self.next_hop.get(fn)
        return out

    def flags(self, fn):
        f = []
        if fn in self.recursive:
            f.append("recursive")
        if fn in self.crosses_indirect:
            f.append("+indirect")
        return ",".join(f)


def demangle(names):
    """Best-effort rustfilt; falls back to the raw symbols."""
    try:
        p = subprocess.run(["rustfilt"], input="\n".join(names),
                           capture_output=True, text=True, check=True)
        out = p.stdout.splitlines()
        return out if len(out) == len(names) else names
    except Exception:
        return names


def disassemble(elf):
    """llvm-objdump first: it is multi-arch, so one host binary reads both
    kernels. GNU objdump is usually host-only and refuses the foreign ELF."""
    last = None
    for tool in ("llvm-objdump", "objdump"):
        try:
            return subprocess.run([tool, "-d", "--no-show-raw-insn", elf],
                                  capture_output=True, text=True, check=True).stdout
        except FileNotFoundError:
            last = f"{tool} not found"
        except subprocess.CalledProcessError as e:
            last = f"{tool} failed: {e.stderr.strip() or e}"
    print(f"stack-depth-gate: could not disassemble {elf} ({last})", file=sys.stderr)
    return None


def read_allowlist(path):
    """-> {symbol: budget}

    The file is blocks: a run of `#` comment lines states WHY that family of
    paths is legitimately deep, then the `<bytes>\\t<symbol>` entries it covers,
    then a blank line ends the block. An entry outside a block is REFUSED —
    an allowlist nobody can audit is how a gate rots into decoration, and the
    reason is the whole point of the file.
    """
    allow, reason = {}, None
    with open(path) as f:
        for n, line in enumerate(f, 1):
            s = line.strip()
            if not s:
                reason = None            # blank line closes the block
                continue
            if s.startswith("#"):
                reason = s.lstrip("# ").strip() or reason
                continue
            try:
                budget, sym = s.split("\t", 1)
                budget = int(budget)
            except ValueError:
                raise SystemExit(f"{path}:{n}: want `<bytes>\\t<symbol>`, got {s!r}")
            if not reason:
                raise SystemExit(
                    f"{path}:{n}: {sym[:60]}… is not under a `#` reason block. "
                    "Every allowlisted path states why it is legitimately deep.")
            allow[sym] = budget
    return allow


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("elf", nargs="?")
    ap.add_argument("--arch", choices=("x86_64", "aarch64"), default="x86_64")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--fail", type=int, default=13000,
                    help="fail when any static path reaches this many bytes")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--include-fatal", action="store_true",
                    help="follow calls into panic/abort handlers too (see is_fatal); "
                         "off by default because panic=abort means those paths never return")
    ap.add_argument("--show-path", action="store_true",
                    help="print the frame-by-frame chain for each reported function")
    ap.add_argument("--allowlist",
                    help="file of `<bytes>\\t<symbol>` for paths that are known-deep. "
                         "Tolerated at or below the recorded budget, so a NEW or "
                         "WORSENED path still fails.")
    ap.add_argument("--write-allowlist", action="store_true",
                    help="rewrite --allowlist from this ELF (reasons must be edited in by hand)")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not args.elf:
        ap.error("an ELF path is required unless --self-test is given")

    text = disassemble(args.elf)
    if text is None:
        return 2
    frames, calls, indirect = parse(text, args.arch, args.include_fatal)
    if not frames:
        print(f"stack-depth-gate: no functions found in {args.elf} — wrong file?", file=sys.stderr)
        return 2

    w = Walker(frames, calls, indirect)
    depth = w.walk_all()
    ranked = sorted(depth.items(), key=lambda kv: -kv[1])
    over = [(n, d) for n, d in ranked if d >= args.fail]

    if args.write_allowlist:
        if not args.allowlist:
            print("stack-depth-gate: --write-allowlist needs --allowlist", file=sys.stderr)
            return 2
        with open(args.allowlist, "w") as f:
            f.write("# Static call paths already at or over the ceiling when the gate\n"
                    "# landed. Tolerated at or below the recorded budget ONLY — a new or\n"
                    "# deeper path fails. Each entry MUST carry a reason; the gate refuses\n"
                    "# to load an entry without one. Burn this list down.\n")
            for n, d in over:
                f.write(f"# TODO: state why this path is legitimately deep.\n{d}\t{n}\n")
        print(f"stack-depth-gate: wrote {len(over)} entries to {args.allowlist} "
              "(add a reason to each before committing)")
        return 0

    allow = read_allowlist(args.allowlist) if args.allowlist else {}
    regressions = [(n, d) for n, d in over if d > allow.get(n, -1)]

    print(f"stack-depth-gate: {args.elf} ({args.arch})")
    print(f"  functions scanned  : {len(frames)}")
    print(f"  unresolved indirect: {sum(1 for v in indirect.values() if v)} function(s) "
          "— their true depth is larger than reported")
    print(f"  recursive          : {len(w.recursive)} function(s) — depth is a lower bound")
    print(f"  >= ceiling ({args.fail}B): {len(over)}")
    shown = ranked[: args.top]
    names = demangle([n for n, _ in shown])
    print(f"  deepest {len(shown)}:")
    for (raw, d), pretty in zip(shown, names):
        note = w.flags(raw)
        print(f"    {d:7d}  {pretty}" + (f"   [{note}]" if note else ""))
        if args.show_path:
            for hop in w.path(raw)[1:]:
                print(f"            +{frames.get(hop, 0):6d}  {hop}")

    if allow:
        print(f"  allowlisted        : {len(over) - len(regressions)} of {len(over)}")

    if regressions:
        print(f"\nstack-depth-gate: FAIL — {len(regressions)} static path(s) reach "
              f">= {args.fail} B on a {16 * 1024} B kernel stack:", file=sys.stderr)
        for name, d in regressions:
            was = allow.get(name)
            print(f"    {d:7d}{f' (budget {was})' if was else ' (new)'}  {name}", file=sys.stderr)
        print("\nSplit the chain so the big frames overlap instead of summing "
              "(Linux `noinline_for_stack`), move the data off-stack, or — if the "
              "path is genuinely this deep — add it to the allowlist WITH a reason.",
              file=sys.stderr)
        return 1
    print("stack-depth-gate: PASS")
    return 0


SELF_TEST_X86 = """
0000000000201000 <root>:
  201000: push   %rbp
  201001: sub    $0x100,%rsp
  201008: call   0000000000202000 <mid>
  20100d: ret

0000000000202000 <mid>:
  202000: sub    $0x1000,%rsp
  202007: movq   $0x0,(%rsp)
  20200f: sub    $0x1000,%rsp
  202016: movq   $0x0,(%rsp)
  20201e: sub    $0x20,%rsp
  202022: call   0000000000203000 <leaf>
  202027: ret

0000000000203000 <leaf>:
  203000: ret

0000000000204000 <indirect_caller>:
  204000: sub    $0x10,%rsp
  204004: call   *%rax
  204006: ret

0000000000205000 <loop_a>:
  205000: sub    $0x40,%rsp
  205004: call   0000000000206000 <loop_b>
  205009: ret

0000000000206000 <loop_b>:
  206000: sub    $0x40,%rsp
  206004: call   0000000000205000 <loop_a>
  206009: ret
"""

SELF_TEST_ARM = """
0000000000301000 <arm_root>:
  301000: stp     x29, x30, [sp, #-0x20]!
  301004: sub     sp, sp, #0x400
  301008: bl      0x302000 <arm_leaf>
  30100c: ret

0000000000302000 <arm_leaf>:
  302000: sub     sp, sp, #16
  302004: ret
"""


def self_test():
    fx, cx, ix = parse(SELF_TEST_X86, "x86_64")
    # 8 (return address) + push 8 + 0x100
    assert fx["root"] == 8 + 8 + 0x100, fx["root"]
    # Probe-split reservation MUST sum across the interleaved stores, or an
    # 8 KiB frame reads as 4096 and the gate misses what it exists to catch.
    assert fx["mid"] == 8 + 0x1000 + 0x1000 + 0x20, fx["mid"]
    assert fx["leaf"] == 8, fx["leaf"]
    assert cx["root"] == {"mid"} and cx["mid"] == {"leaf"}
    assert ix["indirect_caller"] == 1, "`call *%rax` must count as unresolved"

    w = Walker(fx, cx, ix)
    w.walk_all()
    want = fx["root"] + fx["mid"] + fx["leaf"]
    assert w.depth["root"] == want, (w.depth["root"], want)
    assert w.path("root") == ["root", "mid", "leaf"], w.path("root")
    assert "indirect_caller" in w.crosses_indirect
    # A cycle must be REPORTED, not silently collapsed to zero depth.
    assert "loop_a" in w.recursive and "loop_b" in w.recursive, w.recursive

    fa, ca, _ = parse(SELF_TEST_ARM, "aarch64")
    # aarch64 adds no return-address byte: the pre-index stp already saved lr.
    assert fa["arm_root"] == 0x20 + 0x400, fa["arm_root"]
    assert fa["arm_leaf"] == 16, fa["arm_leaf"]
    wa = Walker(fa, ca, {})
    wa.walk_all()
    assert wa.depth["arm_root"] == 0x20 + 0x400 + 16, wa.depth["arm_root"]

    print("stack-depth-gate: self-test PASS (x86_64 + aarch64, probe-split, "
          "recursion, indirect)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
