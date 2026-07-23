## Handoff: kalloc corruption hunt — real ctxsw ABI bug fixed, root cause still open

### Headline
Long-running hunt for a memory-corruption bug that crashes every boot around the
`[ZRAM-SYSFS] disksize=...` event (bare `debug-boot` smoke, ~15-25s repro, recipe
below). This session found and fixed a REAL, independently-valuable register-
clobbering ABI bug in the context-switch path (below) — but a single post-fix boot
still crashed, with a DIFFERENT signature (a non-canonical pointer in a live
`Arc<Dentry>`, not the previous `rip=0` pattern). Per this hunt's OWN established
finding (identical builds crash differently boot-to-boot — see "Non-determinism"
below), one boot cannot confirm or refute whether the ctxsw fix helped. **Root
cause still open.** 9 unrelated real UAF/race bugs fixed+merged earlier this
session (list at bottom) — none were the root cause; don't re-investigate them.

### THIS SESSION'S FIX (real, merged/merging regardless of root-cause status)
`crates/arch/hal-x86_64/src/context.rs`, `Context::switch()`: it calls
`oxide_context_switch(prev, next)` (a hand-written `global_asm!` routine in the
same file) as an ordinary `extern "C"` FFI call, then reads `(*prev).fs_base`
AFTER the call returns. But `oxide_context_switch`'s asm body deliberately
OVERWRITES rsp/rbp/rbx/r12-r15 with the INCOMING task's saved values — that IS the
context switch. This is **exactly the hazard documented in `docs/54 §1.4`**: "an
asm stub that clobbers r12-r15/rbx/rbp across a call must push first." Since the
call site looked like an ordinary FFI call, LLVM was free to assume normal SysV
callee-saved-register semantics and keep `prev` (needed again post-call) live in
r12-r15 across the call — after which it would silently alias whatever the
INCOMING task's `Context` struct happened to store in that exact register slot.
(rbx/rbp are NOT at risk here specifically — this target reserves both from LLVM's
allocator: rbx globally, rbp as the permanent frame pointer per
`"frame-pointer": "always"` — so only r12-r15 needed declaring.)

Fix: route the call through inline `asm!` with explicit `lateout("r12") _` /
`r13`/`r14`/`r15` clobbers + `clobber_abi("C")`, forcing the compiler to spill
`prev`/`next` to the stack (correctly restored by the call/ret discipline when
this exact task resumes) instead of trusting a register. Both arches build clean
(fix is x86_64-only; aarch64's `ContextAArch64::switch` wasn't checked this
session — **worth auditing for the identical hazard**, see next steps).

This is a real, serious, independently-valuable bug regardless of whether it's
THE corruption root cause: a garbled `prev` pointer here causes a wrong CPU
FS_BASE MSR restore (userspace TLS pointer) for whatever task resumes — that alone
is a correctness bug worth having fixed.

### Post-fix result (ONE boot, inconclusive per this hunt's own rules)
`debug-boot,debug-dealloc-diag`, `smp=1`: reached the same `[EXECLOAD tid=4198
systemd-makefs]` / `[wait4 ECHILD]` region as before, then hit a NEW crash shape:
`#GP` (not `#PF`) at `rip=...` inside `<Arc<vfs::dentry::Dentry>>::drop_slow`,
dereferencing a field (`r15`, loaded from `[rbx+0x60]`) that held a **non-canonical
pointer** (`0x80fdc878ffffffff` — upper bits aren't a sign-extension of bit 47,
hence `#GP` not `#PF`). This is DIFFERENT from every prior sample (`rip=0` ret-to-
zero; `InetFileOps` null+0x10; stack-guard-byte corruption at offset 0) — a garbage
(not zeroed) pointer this time, in a completely different subsystem (dcache, not
sched/net). Do NOT treat this as proof the ctxsw fix failed — or as proof it's a
new/different bug — until a proper multi-boot sample is taken (this hunt already
proved identical builds crash differently run-to-run; a single boot after ANY
change is not evidence of anything by itself).

### Mechanism theory explored this session (see also `size_track.rs`, kept in tree)
Explored: kalloc's `add_free_region` (`crates/shared/kalloc/src/holes.rs`) only
validates a freed range against OTHER FREE nodes, never against live allocations
(it doesn't track live blocks at all) — so a caller that calls `dealloc` with an
OVERSIZED `Layout` could silently corrupt a live neighbor with zero detection.
Built `size_track.rs` (bounded live-allocation size ledger, `debug-dealloc-diag`
only, asserts recorded-alloc-size == dealloc-time-size for blocks ≥512B) to test
this directly. **Result: did NOT fire on the `rip=0` sample** (pre-ctxsw-fix boot)
— that specific crash was NOT a dealloc-Layout-mismatch. Keep the tracker (cheap,
real, may still catch a DIFFERENT corruption instance) but this mechanism is now
LESS likely to be the (sole) root cause than the ctxsw register-clobber theory.
A background-agent search for a mismatched alloc/dealloc `Layout` caller (checked
kalloc's own realloc, `debug-heappoison` quarantine, ~15 Linux-KPI allocators with
self-describing headers, ~40 `Box::from_raw`/`Arc::from_raw` sites) found the KPI
layer well-defended structurally; no confirmed instance. Two areas NOT fully
audited: `linux_netdev/napi.rs`'s frag allocator (found to LEAK, not double-free —
ruled out as this bug's cause, but is its own separate minor bug), and ~35 more
`Box::from_raw` sites in `linux_block`/`linux_usb`/`linux_pci`/etc (lower priority,
PMM-page-based not kalloc-based for most of these).

### Post-B1333 multi-boot sample (3 boots, `main` @ `b7780a1c6`)
Per next-step #1 above, took 3 sequential `smp=1` fast-repro boots right after
B1333 merged:
1. **New third crash shape**: `[PANIC] crates/shared/kalloc/src/holes.rs:670:
   kalloc back fragment invalid` — a kalloc-internal assertion (in `alloc()`'s
   back-padding reinsertion) actually CAUGHT something instead of silently
   corrupting. No `[KALLOC]` diagnostic tag printed first (unlike `dealloc`'s
   path, `alloc()`'s back/front-fragment `add_free_region` calls don't currently
   print the failure tag before asserting — a gap worth closing so this fires
   with a tag next time).
2. **No crash — a HANG instead.** Boot progressed dramatically further than
   any prior sample this whole session: past `[ZRAM-SYSFS]`, through PAM/
   dbus-broker/`unix_chkpwd`/session setup, to **49.9s** (~4200 log lines vs the
   usual ~2000-line crash-by-~19s pattern) — then serial output stopped
   advancing entirely across three separate ~30-40s waits (confirmed via
   identical byte-for-byte output size on repeated `qemu_serial` calls). GDB
   `qemu_regs`/`qemu_continue` both timed out (the known GDB-bridge
   unreliability, see memory `qemu-gdb-bridge-unresponsive-on-interrupt.md`) so
   the live CPU state couldn't be inspected. **Ambiguous**: could be (a) a
   genuine NEW deadlock/livelock introduced or exposed by B1333, (b) a
   pre-existing hang-class bug that the fix's timing shift happened to trigger
   instead of the usual crash, or (c) ordinary boot-flakiness (this hunt's own
   docs already note live-gnome-style boots stall ~half the time even on clean
   main). Do not assume B1333 caused this without further evidence — but do not
   dismiss it either.
3. Not yet taken (time-boxed this session) — get to 5 total samples next
   session before drawing conclusions.

**Read as a whole: 3/3 boots this batch reached FURTHER into boot than almost
every pre-B1333 sample, and NONE reproduced the old `rip=0` ret-to-zero
signature.** That's consistent with B1333 having fixed or mitigated a real
contributor — but the new hang (sample 2) and new panic (sample 1) mean the
overall corruption/stability picture is NOT resolved, just changed shape. Next
session: reproduce the hang specifically (does it recur? is it deterministic
at ~49-50s?) and get the holes.rs:670 tag-less panic printing its cause.

### Non-determinism (established fact, don't re-litigate)
Confirmed multiple times this session: identical binaries crash with DIFFERENT
signatures on different boots. A `debug-smp` canary boot (Task stack-guard-byte
check) cleanly caught one instance mid-corruption instead of the usual undefined
crash: `[TASK-STACK-GUARD ... tid=4197 ... offset=0 ...]` — the FIRST byte of a
live 16KiB kernel-stack allocation was already wrong. `debug-smp` does NOT
destabilize the fast repro (earlier suspicion from prior sessions did not
reproduce this session — safe to use).

### Concrete next steps (priority order)
1. **Get a clean multi-boot sample of the ctxsw fix** (3-5 boots, `smp=1`,
   `debug-boot,debug-dealloc-diag`) to actually judge whether `rip=0`-shaped
   crashes stopped recurring. This hunt requires ≥3 samples before attributing
   ANY outcome to a change — see `Lessons learned` in CLAUDE.md ("single boots
   lie about intermittent bugs").
2. **Audit `ContextAArch64::switch` (`crates/arch/hal-aarch64/`) for the identical
   register-clobber hazard** — not checked this session; if aarch64's context-
   switch asm also clobbers callee-saved registers across an ordinary `extern "C"`
   call boundary, it has the same bug and needs the same fix (ARM/x86 lockstep
   rule — CLAUDE.md Discipline #7).
3. Chase the NEW `Arc<Dentry>::drop_slow` non-canonical-pointer sample: find what
   writes `Dentry`'s field at offset `0x60` (likely `d_parent` or similar) and
   whether it can go stale/be freed while a sibling dentry still references it —
   same general "live object read via a reference that outlived its target" shape
   as everything else this hunt has found, just a new victim type.
4. `size_track.rs` stays in tree (`debug-dealloc-diag`) — check its output on
   future samples; it's cheap and may still catch a genuine Layout mismatch for a
   different allocation than the one sampled this session.
5. Do NOT return to the hardware-watchpoint approach (exhausted, PR #3778) or loop
   >2-3 boots chasing one hypothesis without a specific question to answer.

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=1)
mcp__qemu__qemu_continue(...)   # times out at 120s internally, boot continues regardless
# wait ~25-35s, then qemu_serial() and grep for FAULT/PANIC/TASK-STACK-GUARD/size-mismatch
```
Add `debug-smp` for `Task::debug_check_canary`'s stack-guard-byte check (confirmed
NOT to break the boot this session). `debug-heappoison` = same repro but ~500s —
**user has explicitly vetoed this for iteration**, one boot only if truly needed.
Always `qemu_list` + `qemu_stop` stale instances before starting a new one.

### Housekeeping / prior fixes this session (all merged, don't re-investigate)
9 real cross-CPU UAF / logic bugs, none were THE root cause: B1325 (#3767)
corruption-probe fixes. B1326 (#3768) `fd_table`/`mm`/`exe_path` foreign-task
races. B1327/B1328 (#3770/#3772) ext4 `writeback_idxs` stale-frame UAF read.
B1329 (#3773) `parent_arc` race (genuine foreign writer). B1330 (#3774)
`cmdline`/`environ` torn-String reads. B1331 (#3776) `rlimits` foreign-task races.
`ctty` checked clean. `fpu_state` found-not-fixed (ptrace auth gap, own PR needed).
Not audited: `sigactions`/`seccomp_filters`/`posix_timers`/`arch_ctx`. B1332
(#3778) added hw-watchpoint + `[TASK-DROP]` diagnostics (both exhausted/ruled-out
as this session's leads but kept in tree). B1333 (this handoff) = the ctxsw
register-clobber fix + `size_track.rs`.

First command next session: 3-5 sequential `smp=1` boots of current `main` to get
a real sample count on whether `rip=0`-shaped crashes recurred post-B1333.
