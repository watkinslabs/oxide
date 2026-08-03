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

THE BLOCKING TAIL
-----------------
Most syscalls sleep. A path that reaches a scheduling point pays, on top of
whatever it had already spent getting there, the whole cost of `schedule()`
and everything `schedule()` calls before the CPU leaves this stack. Left to
itself the walker under-reports that, because `schedule()` closes a cycle
(it re-enters the tree it was called from), and a back edge is cut: whichever
callers happen to be grey when the cut lands lose the tail entirely.

So the scheduling point is REPLACED by a synthetic sink whose cost is its own
measured subtree depth, computed first, from a walk rooted at it, before any
other function has coloured the graph. As a sink it closes no cycle, so no
edge into it is ever cut, and — being a leaf — it can appear at most once on
any path. A function that can block at four different sites is therefore
charged one tail, not four; a function whose deepest path never blocks keeps
that path, because the walker still takes the maximum over both.

`--no-blocking-tail` turns this off. A missing scheduling point is a hard
error rather than a silent pass: the symbol moving is exactly how this
accounting would rot back into the number that motivated it.

WHAT THE ALLOWLIST IS KEYED ON
------------------------------
The DEMANGLED path (`rust_symbol_identity`), never the mangled symbol. A
mangled name carries a crate disambiguator that changes with the feature set
the crate was built with, so an allowlist keyed on it made the verdict depend
on which build last exported `target/artifacts` — the same tree passed or
failed on build provenance. Identity keeps everything that distinguishes two
functions (generic arguments, closure index, impl self-type) and drops only
the build-dependent parts, and an entry written in the old mangled form still
matches because it is put through the same function.

Identity is many-to-one in two cases the linker allows — one generic
instantiated in two crates, and an LLVM internal-linkage clone next to its
original. A budget therefore covers the DEEPEST symbol sharing that identity,
which is the conservative direction.

A stale entry — an identity that no longer names anything in the ELF — FAILS
rather than being ignored, because an allowlist that silently keeps permission
for paths that are long gone is how the ceiling stops meaning anything.
"""

import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rust_symbol_identity as rsi        # noqa: E402

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


# The one scheduling point: `sched::live::schedule::switch::schedule`. Both
# manglings embed the path with its component lengths, so one substring finds
# it either way. Its wrappers (`park_yield`, `tick_yield`, `sched_yield`) call
# it directly and need no entry of their own — they are ordinary frames on the
# way to the sink.
SCHEDULE_POINT = "5sched4live8schedule6switch8schedule"


def blocking_points(frames):
    """-> sorted symbols that park the caller and run `schedule()`."""
    return sorted(f for f in frames if SCHEDULE_POINT in f)


def with_blocking_tail(frames, calls, indirect, points):
    """-> (frames, calls, tails) with each scheduling point turned into a sink.

    Its cost is its own subtree depth, measured from a walk rooted at it so
    nothing else has coloured the graph first. Collapsing it to a leaf is what
    makes the tail land on every path that can reach it, exactly once.
    """
    tails = {}
    for point in points:
        tails[point] = Walker(frames, calls, indirect).walk(point)
    frames = dict(frames)
    calls = dict(calls)
    for point, tail in tails.items():
        frames[point] = tail
        calls[point] = set()
    return frames, calls, tails


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
    """-> readable names, via the same identity function the allowlist uses.

    No external demangler: a gate whose output depends on whether `rustfilt`
    happens to be installed is the flakiness this file exists to remove.
    """
    return [rsi.identity(n) for n in names]


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
    """-> {identity: (budget, line-number)}

    The file is blocks: a run of `#` comment lines states WHY that family of
    paths is legitimately deep, then the `<bytes>\\t<name>` entries it covers,
    then a blank line ends the block. An entry outside a block is REFUSED —
    an allowlist nobody can audit is how a gate rots into decoration, and the
    reason is the whole point of the file.

    `<name>` is a demangled path, but an entry still carrying a mangled symbol
    from before this was keyed on identity is accepted and normalised, so no
    budget is silently dropped by the format change.
    """
    allow, reason = {}, None
    with open(path) as f:
        for n, line in enumerate(f, 1):
            s = line.rstrip("\n")
            if not s.strip():
                reason = None            # blank line closes the block
                continue
            if s.lstrip().startswith("#"):
                reason = s.strip().lstrip("# ").strip() or reason
                continue
            try:
                budget, sym = s.strip().split("\t", 1)
                budget = int(budget)
            except ValueError:
                raise SystemExit(f"{path}:{n}: want `<bytes>\\t<name>`, got {s.strip()!r}")
            if not reason:
                raise SystemExit(
                    f"{path}:{n}: {sym[:60]}… is not under a `#` reason block. "
                    "Every allowlisted path states why it is legitimately deep.")
            key = rsi.identity(sym.strip())
            prev = allow.get(key)
            if prev and prev[0] != budget:
                raise SystemExit(
                    f"{path}:{n}: {key[:60]}… is already allowed {prev[0]} B at line "
                    f"{prev[1]}. Two budgets for one path is ambiguous; keep one.")
            allow[key] = (budget, n)
    return allow


def index_by_identity(frames):
    """-> {identity: [raw symbol, ...]}. Many-to-one is normal."""
    by_ident = {}
    for raw in frames:
        by_ident.setdefault(rsi.identity(raw), []).append(raw)
    return by_ident


def read_edge_map(path, frames):
    """-> ({caller raw: {callee raw}}, [(line, which, identity) unresolved])

    A `<caller>\\t<callee>` TSV of DEMANGLED identities, one edge per line,
    repeating the caller for a dispatch site with several targets.

    WHY THIS EXISTS. The walker follows direct call edges only, so it stops
    dead at a function pointer — and every hardware interrupt handler in this
    kernel is reached through one. The MSI vector table, the line-handler
    table, the softirq slots, the tick-poll hook and the exit-to-user hook are
    all registered `fn` pointers, so the receive path measured 8 bytes deep
    when its real chain runs to five figures. A gate that reports 8 for the
    deepest path in the kernel is not a conservative gate, it is a blind one.

    The target sets are finite and enumerable: each table has a handful of
    `register_*`/`set_handler` call sites, all in this tree. Naming them here
    makes the edges visible to the walker without teaching it to guess.

    Entries are identities, not mangled symbols, for the same reason the
    allowlist is: a crate disambiguator changes with the features a build
    selects. An entry naming something absent from the ELF is reported for the
    caller to reject — a map that has drifted silently reintroduces exactly the
    blindness it was written to remove.
    """
    by_ident = index_by_identity(frames)
    edges, unresolved = {}, []
    with open(path) as f:
        for n, raw_line in enumerate(f, 1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split("\t") if p.strip()]
            if len(parts) != 2:
                raise SystemExit(f"{path}:{n}: expected `<caller>\\t<callee>`, got {line!r}")
            caller, callee = parts
            callers, callees = by_ident.get(caller), by_ident.get(callee)
            if not callers:
                unresolved.append((n, "caller", caller))
                continue
            if not callees:
                unresolved.append((n, "callee", callee))
                continue
            for c in callers:
                edges.setdefault(c, set()).update(callees)
    return edges, unresolved


def read_roots(path, frames):
    """-> ([raw symbols], [(line, identity) unresolved]) from a file of
    demangled identities, one per line."""
    by_ident = index_by_identity(frames)
    roots, unresolved = [], []
    with open(path) as f:
        for n, raw_line in enumerate(f, 1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            hit = by_ident.get(line)
            if not hit:
                unresolved.append((n, line))
                continue
            roots.extend(hit)
    return roots, unresolved


def verdict(over_by_id, allow, present):
    """-> (fresh, worse, stale, slack). The pass/fail decision, as data.

    Split out of `main` so it can be tested. The accounting below it had a
    positive control and this did not, which is the wrong way round: the
    accounting being right is worth nothing if the layer that turns a number
    into an exit code is wrong.
    """
    fresh = [(k, d, raw) for k, (d, raw) in over_by_id.items() if k not in allow]
    worse = [(k, d, raw, allow[k][0]) for k, (d, raw) in over_by_id.items()
             if k in allow and d > allow[k][0]]
    stale = [(k, allow[k][1]) for k in allow if k not in present]
    slack = [k for k in allow if k in present and k not in over_by_id]
    return fresh, worse, stale, slack


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
    ap.add_argument("--no-blocking-tail", action="store_true",
                    help="do NOT charge paths that reach a scheduling point for the "
                         "cost of schedule() (see THE BLOCKING TAIL); the number then "
                         "describes only a path that never sleeps")
    ap.add_argument("--show-path", action="store_true",
                    help="print the frame-by-frame chain for each reported function")
    ap.add_argument("--allowlist",
                    help="file of `<bytes>\\t<demangled path>` for paths that are "
                         "known-deep. Tolerated at or below the recorded budget, so a "
                         "NEW or WORSENED path still fails.")
    ap.add_argument("--allow-stale", action="store_true",
                    help="report allowlist entries whose path is not in this ELF instead "
                         "of failing on them (they are dead permission either way)")
    ap.add_argument("--write-allowlist", action="store_true",
                    help="rewrite --allowlist from this ELF (reasons must be edited in by hand)")
    ap.add_argument("--indirect-map",
                    help="file of `<caller>\\t<callee>` demangled identities naming the "
                         "targets of function-pointer dispatch sites, so the walker can "
                         "see past them (see read_edge_map)")
    ap.add_argument("--irq-roots",
                    help="file of demangled identities that run on the per-CPU hardirq "
                         "stack rather than a task stack — a SECOND budget domain")
    ap.add_argument("--irq-fail", type=int, default=12000,
                    help="ceiling for the --irq-roots domain. The hardirq stack is the "
                         "same 16384 B, but a hardware interrupt nests into the softirq "
                         "drain, so the drain must leave room for a whole second entry")
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

    # Resolve function-pointer dispatch BEFORE the blocking tail and the walk:
    # an edge added afterwards would not be seen by either.
    resolved_edges = 0
    if args.indirect_map:
        edges, unresolved = read_edge_map(args.indirect_map, frames)
        if unresolved:
            print(f"stack-depth-gate: FAIL — {len(unresolved)} entr(y/ies) in "
                  f"{args.indirect_map} name something not in {args.elf}:", file=sys.stderr)
            for n, which, ident in unresolved:
                print(f"    {args.indirect_map}:{n}  {which} not found: {ident}", file=sys.stderr)
            print("\nThe map exists to make interrupt dispatch visible. An entry that no "
                  "longer resolves silently restores the blindness it was written to "
                  "remove, so a drifted map is a failure, not a warning.", file=sys.stderr)
            return 1
        for caller, callees in edges.items():
            calls[caller].update(callees)
            resolved_edges += len(callees)

    tails = {}
    if not args.no_blocking_tail:
        points = blocking_points(frames)
        if not points:
            print("stack-depth-gate: no scheduling point matching "
                  f"{SCHEDULE_POINT!r} in {args.elf}. Every blocking path would be "
                  "reported without the schedule() tail it really pays; fix the "
                  "match or pass --no-blocking-tail deliberately.", file=sys.stderr)
            return 2
        frames, calls, tails = with_blocking_tail(frames, calls, indirect, points)

    w = Walker(frames, calls, indirect)
    depth = w.walk_all()
    ranked = sorted(depth.items(), key=lambda kv: -kv[1])
    over = [(n, d) for n, d in ranked if d >= args.fail]

    # Identity, not the mangled symbol: see WHAT THE ALLOWLIST IS KEYED ON.
    ident = {raw: rsi.identity(raw) for raw in frames}
    present = set(ident.values())
    # Many-to-one is possible, so a budget covers the DEEPEST symbol sharing
    # the identity — the conservative direction.
    over_by_id = {}
    for n, d in over:
        k = ident[n]
        if k not in over_by_id or d > over_by_id[k][0]:
            over_by_id[k] = (d, n)

    if args.write_allowlist:
        if not args.allowlist:
            print("stack-depth-gate: --write-allowlist needs --allowlist", file=sys.stderr)
            return 2
        with open(args.allowlist, "w") as f:
            f.write("# Static call paths already at or over the ceiling when the gate\n"
                    "# landed. Tolerated at or below the recorded budget ONLY — a new or\n"
                    "# deeper path fails. Entries are DEMANGLED paths, which survive a\n"
                    "# rebuild with different features; each MUST carry a reason, and an\n"
                    "# entry naming a path that no longer exists fails. Burn this down.\n")
            for k, (d, _) in sorted(over_by_id.items(), key=lambda kv: -kv[1][0]):
                f.write(f"# TODO: state why this path is legitimately deep.\n{d}\t{k}\n")
        print(f"stack-depth-gate: wrote {len(over_by_id)} entries to {args.allowlist} "
              "(add a reason to each before committing)")
        return 0

    allow = read_allowlist(args.allowlist) if args.allowlist else {}
    fresh, worse, stale, slack = verdict(over_by_id, allow, present)

    print(f"stack-depth-gate: {args.elf} ({args.arch})")
    print(f"  functions scanned  : {len(frames)}")
    print(f"  unresolved indirect: {sum(1 for v in indirect.values() if v)} function(s) "
          "— their true depth is larger than reported")
    if args.indirect_map:
        print(f"  dispatch resolved  : {resolved_edges} edge(s) from {args.indirect_map} "
              "— interrupt handlers the walker would otherwise stop at")
    print(f"  recursive          : {len(w.recursive)} function(s) — depth is a lower bound")
    for point, tail in tails.items():
        print(f"  blocking tail      : {tail} B charged once to every path reaching "
              f"{point}")
    print(f"  >= ceiling ({args.fail}B): {len(over)}")
    shown = ranked[: args.top]
    names = demangle([n for n, _ in shown])
    print(f"  deepest {len(shown)}:")
    for (raw, d), pretty in zip(shown, names):
        note = w.flags(raw)
        print(f"    {d:7d}  {pretty}" + (f"   [{note}]" if note else ""))
        if args.show_path:
            for hop in w.path(raw)[1:]:
                print(f"            +{frames.get(hop, 0):6d}  {rsi.identity(hop)}")

    if allow:
        held = len(over_by_id) - len(fresh) - len(worse)
        print(f"  allowlisted        : {held} of {len(over_by_id)} over-ceiling path(s)")
        for k in sorted(slack):
            print(f"  slack              : {allow[k][0]} B allowed, now under the "
                  f"ceiling — the entry can go: {k}")

    # ---- second domain: the per-CPU hardirq stack -------------------------
    # A different 16384 B from the task stack, with a different worst case. The
    # entry asm does not re-switch when an interrupt arrives while already on
    # it, and the drain runs with interrupts unmasked, so a hardware interrupt
    # nests onto whatever the softirq drain has already spent. The budget is
    # therefore the stack MINUS a whole second entry, not the stack.
    irq_failed = False
    if args.irq_roots:
        roots, unresolved = read_roots(args.irq_roots, frames)
        if unresolved:
            print(f"\nstack-depth-gate: FAIL — {len(unresolved)} root(s) in "
                  f"{args.irq_roots} are not in {args.elf}:", file=sys.stderr)
            for n, ident in unresolved:
                print(f"    {args.irq_roots}:{n}  {ident}", file=sys.stderr)
            irq_failed = True
        ranked_irq = sorted(((r, depth.get(r, 0)) for r in roots), key=lambda kv: -kv[1])
        over_irq = [(r, d) for r, d in ranked_irq if d >= args.irq_fail]
        print(f"\n  hardirq domain     : {len(roots)} root(s), ceiling {args.irq_fail} B "
              f"of the {16 * 1024} B interrupt stack")
        for raw, d in ranked_irq[: args.top]:
            note = w.flags(raw)
            print(f"    {d:7d}  {rsi.identity(raw)}" + (f"   [{note}]" if note else ""))
        if over_irq:
            print(f"\nstack-depth-gate: FAIL — {len(over_irq)} interrupt-stack path(s) "
                  f"reach >= {args.irq_fail} B:", file=sys.stderr)
            for raw, d in over_irq:
                print(f"    {d:7d}  {rsi.identity(raw)}", file=sys.stderr)
            print("\nThis stack takes a nested hardware interrupt on top of whatever the "
                  "softirq drain has already spent, so the headroom left here is what a "
                  "second entry has to fit in. Shorten the chain; raising the ceiling "
                  "spends headroom that the nesting needs.", file=sys.stderr)
            irq_failed = True

    # The two failures need OPPOSITE responses, so they are never merged into
    # one list: a NEW or WORSENED path is code to fix, a STALE entry is a line
    # to delete.
    if fresh or worse:
        print(f"\nstack-depth-gate: FAIL — {len(fresh) + len(worse)} static path(s) reach "
              f">= {args.fail} B on a {16 * 1024} B kernel stack:", file=sys.stderr)
        for k, d, raw in sorted(fresh, key=lambda t: -t[1]):
            print(f"    {d:7d}  NEW       {k}", file=sys.stderr)
            print(f"             (symbol {raw})", file=sys.stderr)
        for k, d, raw, was in sorted(worse, key=lambda t: -t[1]):
            print(f"    {d:7d}  WORSENED  {k}  (budget {was}, +{d - was})", file=sys.stderr)
            print(f"             (symbol {raw})", file=sys.stderr)
        print("\nSplit the chain so the big frames overlap instead of summing "
              "(Linux `noinline_for_stack`), move the data off-stack, or — if the "
              "path is genuinely this deep — add it to the allowlist WITH a reason.",
              file=sys.stderr)
    if stale and not args.allow_stale:
        print(f"\nstack-depth-gate: FAIL — {len(stale)} allowlist entr(y/ies) name a path "
              f"that is not in {args.elf} at all:", file=sys.stderr)
        for k, line in sorted(stale, key=lambda t: t[1]):
            print(f"    {args.allowlist}:{line}  STALE  {k}", file=sys.stderr)
        print("\nDelete those lines. This is NOT a depth regression — the path is gone, "
              "and an allowlist that keeps permission for code that no longer exists "
              "stops meaning anything. If the symbol only vanishes in the build you are "
              "checking, check the build the list was recorded against instead of "
              "passing --allow-stale.", file=sys.stderr)
    if fresh or worse or (stale and not args.allow_stale) or irq_failed:
        return 1
    if stale:
        print(f"  stale (ignored)    : {len(stale)} entr(y/ies) name a path not in this ELF")
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

# A blocking path, shaped like the real one: `schedule` closes a cycle back
# into its own subtree, two different call sites reach it, and a sibling
# branch never sleeps. Costs include the 8 B x86_64 return address.
SELF_TEST_BLOCK = """
0000000000401000 <sleeper>:
  401000: sub    $0x100,%rsp
  401007: call   0000000000402000 <waiter>
  40100c: call   0000000000405000 <cold_leaf>
  401011: ret

0000000000402000 <waiter>:
  402000: sub    $0x10,%rsp
  402004: call   0000000000403000 <_ZN5sched4live8schedule6switch8schedule17habcE>
  402009: call   0000000000402100 <waiter2>
  40200e: ret

0000000000402100 <waiter2>:
  402100: sub    $0x10,%rsp
  402104: call   0000000000403000 <_ZN5sched4live8schedule6switch8schedule17habcE>
  402109: ret

0000000000403000 <_ZN5sched4live8schedule6switch8schedule17habcE>:
  403000: sub    $0x20,%rsp
  403004: call   0000000000404000 <switch_tail>
  403009: ret

0000000000404000 <switch_tail>:
  404000: sub    $0x200,%rsp
  404007: call   0000000000404100 <blocked_helper>
  40400c: ret

0000000000404100 <blocked_helper>:
  404100: sub    $0x40,%rsp
  404104: call   0000000000403000 <_ZN5sched4live8schedule6switch8schedule17habcE>
  404109: ret

0000000000408000 <reaper>:
  408000: sub    $0x80,%rsp
  408007: call   0000000000404100 <blocked_helper>
  40800c: ret

0000000000405000 <cold_leaf>:
  405000: sub    $0x30,%rsp
  405004: ret

0000000000406000 <chooser>:
  406000: call   0000000000402000 <waiter>
  406005: call   0000000000407000 <huge_leaf>
  40600a: ret

0000000000407000 <huge_leaf>:
  407000: sub    $0x400,%rsp
  407007: ret
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

    fb, cb, ib = parse(SELF_TEST_BLOCK, "x86_64")
    sched = [f for f in fb if SCHEDULE_POINT in f]
    assert blocking_points(fb) == sched and len(sched) == 1, sched
    sched = sched[0]
    plain = Walker(fb, cb, ib)
    plain.walk_all()
    fb2, cb2, tails = with_blocking_tail(fb, cb, ib, [sched])
    # 8 + 0x20, then the switch tail and the helper it re-enters; the helper's
    # edge back into `schedule` is the cycle, cut once and flagged.
    assert tails[sched] == (8 + 0x20) + (8 + 0x200) + (8 + 0x40), tails
    assert cb2[sched] == set(), "the scheduling point must become a sink"

    wb = Walker(fb2, cb2, ib)
    wb.walk_all()
    tail = tails[sched]
    # `waiter` reaches the tail directly AND through `waiter2`. It pays for one.
    assert wb.depth["waiter"] == (8 + 0x10) + (8 + 0x10) + tail, wb.depth["waiter"]
    assert wb.depth["sleeper"] == (8 + 0x100) + wb.depth["waiter"], wb.depth["sleeper"]
    # The tail is what a blocking path costs, not a tax on every path: a branch
    # that never sleeps keeps its own depth ...
    assert wb.depth["cold_leaf"] == 8 + 0x30, wb.depth["cold_leaf"]
    # ... and a caller whose deepest branch never sleeps keeps THAT branch.
    assert wb.depth["chooser"] == 8 + (8 + 0x400), wb.depth["chooser"]
    # The whole point. `blocked_helper` sits INSIDE the scheduling point's own
    # subtree, so its edge back to `schedule` is the back edge the plain walker
    # cuts — and every other caller of it, `reaper` here, inherits a depth with
    # no tail in it at all. That is the number this accounting exists to fix.
    assert plain.depth["reaper"] == (8 + 0x80) + (8 + 0x40), plain.depth["reaper"]
    assert wb.depth["reaper"] == (8 + 0x80) + (8 + 0x40) + tail, wb.depth["reaper"]

    identity_self_test()
    verdict_self_test()
    print("stack-depth-gate: self-test PASS (x86_64 + aarch64, probe-split, "
          "recursion, indirect, blocking tail, allowlist identity, verdict)")
    return 0


def verdict_self_test():
    """The layer that turns a number into an exit code, with a positive control.

    Everything below this was tested and this was not, which is the wrong way
    round: correct accounting feeding a broken decision still merges the defect.
    Each case asserts BOTH that the intended verdict fires and that the others
    stay empty, so a rule that fires on everything cannot pass.
    """
    present = {"a", "b"}

    # Clean: over nothing, allow nothing.
    assert verdict({}, {}, present) == ([], [], [], [])

    # A NEW over-ceiling path with no allowlist entry must be `fresh`.
    fresh, worse, stale, slack = verdict({"a": (14000, "_ZN1a")}, {}, present)
    assert [k for k, _, _ in fresh] == ["a"], fresh
    assert (worse, stale, slack) == ([], [], [])

    # Allowlisted AT the recorded budget is tolerated and reported as neither.
    fresh, worse, stale, slack = verdict({"a": (14000, "_ZN1a")}, {"a": (14000, 7)}, present)
    assert (fresh, worse, stale, slack) == ([], [], [], [])

    # One byte DEEPER than the budget must be `worse`, not silently held. This
    # is the control that matters: a ratchet that accepts `>=` instead of `>`
    # lets a path grow without limit, one byte at a time, and every run passes.
    fresh, worse, stale, slack = verdict({"a": (14001, "_ZN1a")}, {"a": (14000, 7)}, present)
    assert [(k, d, was) for k, d, _, was in worse] == [("a", 14001, 14000)], worse
    assert (fresh, stale, slack) == ([], [], [])

    # An entry naming a path absent from the ELF is `stale` — dead permission.
    fresh, worse, stale, slack = verdict({}, {"gone": (9000, 3)}, present)
    assert stale == [("gone", 3)], stale
    assert (fresh, worse, slack) == ([], [], [])

    # Present, allowed, but now under the ceiling: the entry can go.
    fresh, worse, stale, slack = verdict({}, {"a": (9000, 3)}, present)
    assert slack == ["a"], slack
    assert (fresh, worse, stale) == ([], [], [])


# Two builds of one tree, differing only in the crate disambiguator — the
# provenance dependence that made this gate's verdict unreliable.
BUILD_A = "_RNvNtNtCseQ963CMHBD6_5kmain5kmain5entry11kernel_main"
BUILD_B = "_RNvNtNtCs1Yf3GkQE07G_5kmain5kmain5entry11kernel_main"


def identity_self_test():
    import tempfile

    rsi.self_test()
    # The defect in one line: the gate must not care which build it reads.
    assert BUILD_A != BUILD_B
    assert rsi.identity(BUILD_A) == rsi.identity(BUILD_B) == \
        "kmain::kmain::entry::kernel_main"

    def allowlist(text):
        f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        f.write(text)
        f.close()
        return f.name

    # An entry written in the OLD mangled form still matches the identity of a
    # DIFFERENT build's symbol: the format change drops no budget.
    path = allowlist(f"# reason\n19920\t{BUILD_A}\n")
    allow = read_allowlist(path)
    assert allow == {"kmain::kmain::entry::kernel_main": (19920, 2)}, allow
    assert rsi.identity(BUILD_B) in allow

    # Demangled entries are the written form, and re-reading one is a no-op.
    path = allowlist("# reason\n19920\tkmain::kmain::entry::kernel_main\n")
    assert read_allowlist(path)["kmain::kmain::entry::kernel_main"][0] == 19920

    # Same path recorded twice with different budgets is ambiguous, not a
    # silent last-wins.
    path = allowlist(f"# reason\n19920\t{BUILD_A}\n19000\t{BUILD_B}\n")
    try:
        read_allowlist(path)
        raise AssertionError("two budgets for one identity must be refused")
    except SystemExit:
        pass

    # A budget covers the deepest symbol sharing its identity, which is what
    # keeps the many-to-one cases (one generic instantiated in two crates, an
    # LLVM clone beside its original) from letting a regression through.
    frames = {BUILD_A: 100, BUILD_A + ".llvm.4242": 100}
    over = [(BUILD_A, 13000), (BUILD_A + ".llvm.4242", 14000)]
    ident = {raw: rsi.identity(raw) for raw in frames}
    by_id = {}
    for n, d in over:
        k = ident[n]
        if k not in by_id or d > by_id[k][0]:
            by_id[k] = (d, n)
    assert len(by_id) == 1 and by_id["kmain::kmain::entry::kernel_main"][0] == 14000, by_id

    # Stale is a different verdict from new: the identity is in the allowlist
    # but names nothing in the ELF.
    allow = read_allowlist(allowlist("# reason\n19920\tkmain::gone::forever\n"))
    present = set(ident.values())
    assert [k for k in allow if k not in present] == ["kmain::gone::forever"]
    assert [k for k in allow if k in present] == []
    return 0


if __name__ == "__main__":
    sys.exit(main())
