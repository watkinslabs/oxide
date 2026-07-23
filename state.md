## Handoff: kalloc corruption hunt — localized to a Weak<SuperBlock> field in Dentry

### Headline
Long-running hunt for a memory-corruption bug that crashes every boot around the
`[ZRAM-SYSFS] disksize=...` event (bare `debug-boot` smoke, ~15-25s repro, recipe
below). This session fixed a real register-clobbering ABI bug in the context-switch
path (B1333, merged) — after which the OLD dominant crash shape (`rip=0` ret-to-
zero) stopped recurring across 5 post-fix boots, replaced by 4 DIFFERENT shapes.
**Two of those 5 boots independently crashed in the exact same function**,
`<Arc<vfs::dentry::Dentry>>::drop_slow`, decrementing what disassembly proves is a
`Weak<T>`-shaped field that held **raw NULL** instead of either a valid pointer or
`Weak`'s own legitimate "empty" sentinel. This is the most specific, reproducible
lead of the entire hunt — **not yet fixed**, that's the next task. Root cause still
open. 9 unrelated real UAF/race bugs fixed+merged earlier this session (list at
bottom) — none were the root cause; don't re-investigate them.

### THE LEAD: `Dentry`'s `sb: Weak<SuperBlock>` field found NULL
`crates/kernel/vfs/src/dentry.rs:87`: `sb: Weak<SuperBlock>` — doc comment: "the SB
owns `s_root` (strong) and outlives every dentry; making this strong would form an
Arc cycle... Default `Weak::new()` for dentries built before their fs owns a
SuperBlock." So a Dentry's `sb` field is ALWAYS either a real live pointer or the
`Weak::new()` empty sentinel — never anything else, by construction.

Two independent boots this session crashed inside `Dentry::drop_slow` decrementing
this exact shape of field:
- Boot A: `#GP` (non-canonical pointer, `0x80fdc878ffffffff`) at
  `mov 0x28(%r15),%rax` reading through a similarly-shaped field.
- Boot B: `#PF` write fault, `cr2=0x8` (null+8), at `lock decq 0x8(%rdi)` — the
  disassembly around it (`objdump -d`) shows: `mov 0x40(%rbx),%rdi; cmp
  $0xffffffffffffffff,%rdi; je <skip>; lock decq 0x8(%rdi)`. The `cmp` against
  `0xffffffffffffffff` (not `0`) is the compiler's check for `Weak::new()`'s
  dangling sentinel — proving this field is a `Weak<T>`, not an `Option<Arc<T>>`
  (which niches on `0`/NULL for `None`). `rdi` was found to be **raw `0`** — a
  value this field should structurally never hold (only a real pointer or
  `0xffffffffffffffff`).

**Next step (highest priority)**: find every place that writes to `Dentry.sb`
(grep `\.sb\s*=` and `Weak::new()` assignments in `crates/kernel/vfs/src/`) and
every place that constructs/moves/drops a `Dentry` via anything other than normal
`Weak` assignment (raw `mem::zeroed`, `MaybeUninit`, manual field writes, a
realloc/resize path, `ptr::write_bytes`, etc.). The `-1`-vs-`0` distinction is the
smoking gun: whoever put `0` there did NOT go through `Weak::new()` or a normal
`Weak` clone/assignment (both produce `0xffff...ff`, never raw `0`) — it's either
(a) a `mem::zeroed()`/`MaybeUninit::zeroed()` Dentry that skipped proper Weak
initialization, or (b) an external write (the same "narrow zero write into live
memory" pattern every sample this whole hunt has shown) landing on this exact
field. Check both `Dentry::new`/`new_child`-style constructors AND whether
anything ever bulk-zeroes a `Dentry`-sized memory region (e.g., a slab/pool
reuse path, or kalloc handing back zeroed memory that a Dentry gets placed into
without every field being explicitly initialized).

### B1333: the ctxsw register-clobber fix (merged, real, keep)
`crates/arch/hal-x86_64/src/context.rs`, `Context::switch()` called
`oxide_context_switch` (hand-written asm that deliberately clobbers
rsp/rbp/rbx/r12-r15 — that IS the context switch) as an ordinary `extern "C"` FFI
call, then read `(*prev).fs_base` AFTER the call returned. Per `docs/54 §1.4`
("an asm stub that clobbers r12-r15/rbx/rbp across a call must push first"), that
call shape let LLVM assume normal SysV callee-saved semantics and keep `prev`
live in a register across the call — silently aliasing whatever the incoming
task's `Context` stored in that exact slot. Fixed via inline `asm!` with explicit
r12-r15 clobbers (rbx/rbp are LLVM-reserved on this target already). Both arches
build clean; fix is x86_64-only — **`ContextAArch64::switch` not yet audited for
the identical hazard, do that before calling ARM/x86 lockstep satisfied.**

### C156/C157: kalloc diagnostic-tag gaps (merged, real, keep)
`HoleList::add_free_region`/`try_merge` had FIVE silently-untagged `Err`-return
paths (found by chasing a real `kalloc back fragment invalid` panic that produced
zero `[KALLOC]` diagnostic output despite `debug-dealloc-diag` being on) — every
sibling check in the same functions already printed a tag; these five used bare
`?`/`.ok_or(...)?` and skipped it. All five now tagged. Diagnostic-only, no
behavior change. If a kalloc panic fires again, the tag will now say which
specific branch and addresses were involved — use it.

### Post-B1333 sample count: 5 boots, 4 different crash shapes, 0 repeats of `rip=0`
1. `holes.rs` `kalloc back fragment invalid` (untagged at the time; now tagged
   via C156/C157 — re-run to get the actual addresses next time this fires).
2. A ~50s HANG past the previous crash point (past PAM/dbus-broker/session setup)
   — GDB unresponsive, couldn't inspect. Ambiguous: new bug vs. pre-existing
   flakiness (this hunt's own docs already note live-gnome-style boots stall
   sometimes on clean main). Not yet reproduced a second time.
3. Same `holes.rs` panic again (before the C157 tag fix landed).
4. `Arc<Dentry>::drop_slow` `#GP`, non-canonical `Weak`-shaped field.
5. `Arc<Dentry>::drop_slow` `#PF` write null+8, same `Weak`-shaped field, NULL.

**Read as a whole**: the dominant `rip=0` signature is gone across all 5 samples
— consistent with B1333 having fixed or mitigated a real contributor. But the
Dentry `Weak<SuperBlock>` corruption (samples 4+5, same function, same field
shape) is now the clearest, most specific remaining lead — chase it directly
next session per "THE LEAD" above.

### Non-determinism (established fact, don't re-litigate)
Confirmed multiple times: identical binaries crash with DIFFERENT signatures on
different boots. A `debug-smp` canary boot (Task stack-guard-byte check) cleanly
caught one instance mid-corruption instead of the usual undefined crash — confirms
`debug-smp` does NOT destabilize the fast repro (a prior-session suspicion that
did not reproduce this session). Never attribute a fix from fewer than 3-5 boots.

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=1)
mcp__qemu__qemu_continue(...)   # times out at 120s internally, boot continues regardless
# wait ~25-35s, then qemu_serial() and grep for FAULT/PANIC/KALLOC/TASK-STACK-GUARD
```
Add `debug-smp` for the stack-guard-byte canary. `debug-heappoison` = same repro
but ~500s — **user has explicitly vetoed this for iteration**, one boot only if
truly needed. Always `qemu_list` + `qemu_stop` stale instances before starting a
new one. When a fault hits `Arc<...>::drop_slow` or similar generic drop glue,
`addr2line -Cfi -e <elf> <rip>` + `objdump -d --start-address=... --stop-address=...`
around it reliably identifies the exact field/offset — this is how the Dentry
lead was found, do the same for any new sample.

### Housekeeping / prior fixes this session (all merged, don't re-investigate)
9 real cross-CPU UAF / logic bugs, none were THE root cause: B1325 (#3767)
corruption-probe fixes. B1326 (#3768) `fd_table`/`mm`/`exe_path` foreign-task
races. B1327/B1328 (#3770/#3772) ext4 `writeback_idxs` stale-frame UAF read.
B1329 (#3773) `parent_arc` race (genuine foreign writer). B1330 (#3774)
`cmdline`/`environ` torn-String reads. B1331 (#3776) `rlimits` foreign-task races.
`ctty` checked clean. `fpu_state` found-not-fixed (ptrace auth gap, own PR needed).
Not audited: `sigactions`/`seccomp_filters`/`posix_timers`/`arch_ctx`. B1332
(#3778) hw-watchpoint + `[TASK-DROP]` diagnostics (exhausted/ruled out as leads,
kept in tree). B1333 (#3779) ctxsw register-clobber fix. C156/C157 (#3780 + this
handoff) kalloc diagnostic-tag gaps. `size_track.rs` (kept, `debug-dealloc-diag`)
did not fire on any sample yet — keep watching it.

First command next session: `grep -rn "\.sb\s*=\|Weak::new()" crates/kernel/vfs/src/dentry.rs crates/kernel/vfs/src/*.rs` per "THE LEAD" above — find what writes `Dentry.sb` and whether any Dentry construction path skips proper `Weak` initialization.
