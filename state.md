## Handoff: kalloc corruption hunt — 2 more real UAFs fixed, root cause still open

### Headline
Long-running hunt for a memory-corruption bug that crashes every boot around the
`[ZRAM-SYSFS] disksize=...` event (bare `debug-boot` smoke, ~15-25s repro, recipe
below). This session: fixed a real register-clobbering ABI bug in context-switch
(B1333); closed silent-diagnostic gaps in kalloc (C156-158) that let a real
`malformed-free-size addr=... size=0` sample be captured with full context for
the first time — the ORIGINAL signature this hunt started from; ran a 6-agent
sweep of every `Arc::into_raw`/`from_raw` site in the kernel and found+fixed TWO
more real UAFs (B1334, B1335 — see below). **Root cause still open** — a 10th
distinct crash shape appeared in the heap-GROWTH path (new territory, not yet
investigated) on the first boot after B1335. 9 unrelated real UAF/race bugs from
earlier this session (list at bottom) — none were the root cause either.

### B1334 + B1335: two more real UAFs found via systematic sweep (merged)
Dispatched 5 parallel agents to audit all 16 files in the kernel containing
`Arc::into_raw`/`Arc::from_raw`, checking each against the shape of the
already-fixed `switched_from->on_cpu` bug (raw pointer read/written after the
Arc it derived from could have already dropped on a different path). 14 of 16
files were clean (careful, correctly-locked code). Two real bugs found and fixed:
- **B1334** (`mm-vmm/src/rmap.rs`, `PageRmap::anon_vma()`): loaded a raw
  `AtomicPtr<AnonVma>` then called `Arc::increment_strong_count` with no lock,
  racing `set_anon_vma`/`clear_anon_vma`'s swap-then-drop. Fixed by replacing the
  raw pointer with `Spinlock<Option<Arc<AnonVma>>>`, mirroring `FileRmap`
  (already correct) in the same crate. **`PageRmap` has zero callers anywhere in
  the tree — this is currently dead code.** Real bug, unlikely to be THE root
  cause.
- **B1335** (`syscalls/pvmrw_common.rs` + `310_process_vm_readv.rs` +
  `311_process_vm_writev.rs`): `target_root_pa()` cloned the foreign task's
  `Arc<AddressSpace>` just to read `root_pa`, then dropped the Arc at return —
  BEFORE the caller's chunked iovec copy loop even ran. If the target task
  exits/execve's mid-loop, `read_foreign_user`/`write_foreign_user` walk/write
  through a stale `root_pa` whose physical frames may already be freed and
  reused — `process_vm_writev` can write into freed-and-reallocated physical
  memory. Fixed by returning the `Arc` itself (renamed `target_mm()`) and
  holding it alive for the whole copy loop, matching every other foreign-mm
  caller (`ptrace`, `process_madvise`, `process_mrelease`, procfs `pid_files`).
  **This IS a live, reachable syscall path (gdb/strace-style debuggers use it)
  — a stronger root-cause candidate than B1334.**

One boot immediately after B1335 merged did NOT confirm or refute it (see below)
— per this hunt's own established non-determinism, needs 3-5 samples, not one.

### NEW territory: heap-GROWTH path crash (1 sample, not yet investigated)
Post-B1335 boot (`smp=1`, `debug-boot,debug-dealloc-diag`) hit a crash shape
NEVER SEEN before this session — not free-list corruption, but kalloc's
heap-growth registration itself failing:
```
[KALLOC] growth-register-failed addr=ffff800078100000 size=1048576 tag=outside-owned-region
[PANIC] crates/shared/kalloc/src/lib.rs:682: kalloc grow region invalid
```
This is `HoleList::add_region` (`holes.rs`) successfully validating and
registering a new `RegionHdr`, then its own trailing call to
`add_free_region(usable, end - usable)` failing `owns_range` against the region
it JUST inserted — which should be structurally impossible if `add_region`'s
own math is self-consistent (it already validates `end - usable >= MIN_HOLE_SIZE`
before ever reaching that call). Two hypotheses, neither checked yet:
(a) a genuine off-by-one/alignment bug in `add_region`'s `usable`/`end`
computation vs. what `owns_range` independently checks, or (b) the PMM growth
callback (`f(need, memcg)` in `KAlloc::alloc`, `lib.rs`) handed back a region
`(addr, size)` that overlaps/aliases something already registered, corrupting
`self.regions`' linked list before this point (a PMM-side bug, not kalloc's own
math). **First concrete next step: reproduce this specific tag 2-3 times, and
if it recurs, read `KAlloc::alloc`'s growth path (`lib.rs` lines ~606-679) and
whatever PMM function backs the `grow_hook` for a region-overlap or double-grow
bug.** This is genuinely new ground — not yet touched by anything else this
session's diagnostics/fixes address.

### Still-standing lead from before this pass: dcache is a frequent victim, not source
3 of 9 crash samples before this pass hit dcache/`Dentry` code (`drop_slow` x2,
a `DENTRY_HASHTABLE`-adjacent NULL-in-`Vec<Arc<Dentry>>`). Read `dcache/hash.rs`
and `dcache/lifecycle.rs` end-to-end — both correctly locked/ordered, no bug
found. dcache is high-churn (Arc/Dentry-heavy) so it's likely the most FREQUENT
victim by chance, not the source. Don't keep narrowing inside dcache without new
evidence.

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=1)
mcp__qemu__qemu_continue(...)   # times out at 120s internally, boot continues regardless
# wait ~25-35s, then qemu_serial() and grep for FAULT/PANIC/KALLOC/TASK-STACK-GUARD
```
Add `debug-smp` for the stack-guard-byte canary (confirmed safe, doesn't
destabilize the repro). `debug-heappoison` = same repro but ~500s — **user has
explicitly vetoed this for iteration**, one boot only if truly needed. Always
`qemu_list` + `qemu_stop` stale instances first. `nm -C <elf> | sort` +
nearest-below lookup, and `addr2line -Cfi` + `objdump -d
--start-address=... --stop-address=...` around a faulting `rip`, are the two
techniques that found every lead this session — use them before GDB (confirmed
repeatedly unreliable post-fault/post-panic here).

### Non-determinism (established, don't re-litigate)
10 distinct crash shapes seen this session across ~15 boots, on unmodified or
lightly-modified builds. Never attribute a fix from fewer than 3-5 boots.

### Concrete next steps (priority order)
1. **Chase the NEW heap-growth crash** (`growth-register-failed
   tag=outside-owned-region`) — see above, genuinely unexplored territory.
2. Get 3-5 more `smp=1` boots on current `main` (post-B1334/B1335) and tally
   crash shapes — specifically check whether `rip=0` (fixed by B1333) or the
   dcache-NULL family (never explained) recur, to judge whether either fix
   family actually helped.
3. Audit `ContextAArch64::switch` (`crates/arch/hal-aarch64/`) for the same
   register-clobber hazard B1333 fixed on x86_64 — still not checked, needed
   for ARM/x86 lockstep (CLAUDE.md Discipline #7).
4. Do NOT return to the hardware-watchpoint approach (exhausted, PR #3778) or
   loop boots without a specific question to answer.

### Housekeeping (all merged, don't re-investigate; SHAs/details in git log)
9 real cross-CPU UAF/logic bugs from earlier this session (Task field races:
`fd_table`/`mm`/`exe_path`/`parent_arc`/`cmdline`/`environ`/`rlimits`; ext4
`writeback_idxs` UAF; corruption-probe fixes) — `ctty` clean; `fpu_state`
found-not-fixed (ptrace auth gap, own PR needed); `sigactions`/
`seccomp_filters`/`posix_timers`/`arch_ctx` not audited. B1332 hw-watchpoint +
`[TASK-DROP]` diagnostics (leads exhausted, kept). B1333 ctxsw register-clobber
fix. C156-C160: kalloc diagnostic-tag gaps + `size_track.rs` (kept, still never
fired — the mismatched-Layout theory is weak). B1334/B1335 (this pass): rmap
TOCTOU (dead code) + process_vm_readv/writev foreign-AS UAF (live path).

First command next session: boot `smp=1` `debug-boot,debug-dealloc-diag` 2-3
times, grep for `growth-register-failed` — if it recurs, read `KAlloc::alloc`'s
growth path in `crates/shared/kalloc/src/lib.rs` (~line 606-679) and the PMM
`grow_hook` backing function next to it.
