## Handoff: kalloc corruption hunt — diagnostics now firing correctly, exact address captured

### Headline
Long-running hunt for a memory-corruption bug that crashes every boot around the
`[ZRAM-SYSFS] disksize=...` event (bare `debug-boot` smoke, ~15-25s repro, recipe
below). This session: (1) fixed a real register-clobbering ABI bug in the context-
switch path (B1333, merged) — the OLD dominant crash shape (`rip=0` ret-to-zero)
stopped recurring across 6 post-fix boots; (2) closed several silent-diagnostic
gaps in kalloc (C156/C157, merged) that were causing corruption events to panic
with ZERO context; (3) **with those gaps closed, captured the clearest sample of
the whole hunt**: `[KALLOC] malformed-free-size addr=ffffffff81a6b7f8
size=0000000000000000` — a real free-list `HoleHdr` at a known address with its
`size` field zeroed to exactly 0, immediately followed by a legitimate large
(512 KiB) dealloc failing list validation (`kalloc invalid free`, `lib.rs:807`).
This is the ORIGINAL corruption signature this entire hunt started from ("a
corrupted free-list node had size=0x0...0 — a zeroed page-aligned pattern"), now
reproduced with full diagnostic context for the first time. **Root cause still
open** — this is a data point, not yet a fix. 9 unrelated real UAF/race bugs
fixed+merged earlier this session (list at bottom) — none were the root cause;
don't re-investigate them.

### THE CLEAREST LEAD: a live-captured zeroed `HoleHdr.size`
Sample (boot: `debug-boot,debug-dealloc-diag`, `smp=1`, ~23s into boot, right
after `[TASK-DROP] tid=4197 ...`, at the usual `[ZRAM-SYSFS] disksize=...`
trigger):
```
[KALLOC] malformed-free-size addr=ffffffff81a6b7f8 size=0000000000000000
[KALLOC] dealloc-failed tag=malformed-node ptr=ffffffff821cbdd0 size=524288 align=8
[PANIC] crates/shared/kalloc/src/lib.rs:807: kalloc invalid free
```
`addr=ffffffff81a6b7f8` resolves (via `nm -C <elf> | sort` + nearest-below lookup)
only as far as `kalloc::STATIC_HEAP` (no finer-grained symbol — expected, it's
heap data). This address did NOT fall inside any `[TASK-DROP]`-logged freed
task-stack range from the same boot (checked programmatically). **Next session:
get 2-3 more samples of this EXACT tag (`malformed-free-size`) and check whether
the corrupted address recurs, or is different each time** — that answers whether
this is a fixed/recurring victim (points at a specific allocation-site bug) or
genuinely random (points at a wild-pointer/UAF source unrelated to what's there).

`size_track.rs`'s threshold was lowered this session from 512B to 96B (a Dentry-
sized live corruption sample, see below, is well under 512B — the original
threshold structurally could never have caught it). **Still did not fire** on
this sample either — the `HoleHdr` at `ffffffff81a6b7f8` was not one `size_track`
was watching, OR (more likely, since `size_track` only tracks the ORIGINAL
allocation, not free-list nodes after coalescing) the corrupted node itself isn't
directly traceable to a single mismatched `dealloc` call this way. This further
weakens (but doesn't fully rule out) the "caller passes an oversized Layout"
theory — leaning the evidence back toward a genuine wild write (something writing
8 zero bytes to an address it doesn't own) as the more likely mechanism.

### SECONDARY LEAD (same corruption family, different session boot): Dentry.sb
Two other post-B1333 boots independently crashed inside
`<Arc<vfs::dentry::Dentry>>::drop_slow`, decrementing a `Weak<T>`-shaped field
(disassembly-confirmed via the compiler's `-1`-dangling-sentinel check, not a
`0`-niched `Option<Arc<T>>`) that held raw NULL. `crates/kernel/vfs/src/
dentry/constructors.rs` was audited end-to-end this session — **every** Dentry
construction path (`new`/`new_negative`/`new_root`/`new_child`/`new_root_in_sb`/
`new_anon`/`new_pseudo`) uses either `Weak::new()` or `Arc::downgrade(...)`, both
always well-formed. Localizes to `Dentry.sb: Weak<SuperBlock>`
(`crates/kernel/vfs/src/dentry.rs:87`) but the corruption source is NOT in
dentry.rs itself — confirms (doesn't newly discover) that this is the same
generic external corruptor landing on a different victim type, same as
`HoleHdr`, `Task` stack-guard bytes, `Task.tgid`, an `InetFileOps`-reachable
field, and a context-switch saved-RIP slot earlier this session. **The pattern
across EVERY sample this whole hunt, now ~10 distinct victims across 2 sessions,
is a narrow (4-16 byte) write of ZERO (or in 2 cases, garbage) landing on a small
fixed offset within an otherwise-live, otherwise-valid object.** No sample has
ever pointed at code that legitimately owns the victim object — always someone
else's write reaching in from outside.

### Concrete next steps (priority order)
1. **Get 2-3 more `malformed-free-size` samples** (now that C156/C157 make this
   tag reliable) and check address recurrence — see "THE CLEAREST LEAD" above.
   This is now the cheapest, most information-dense repro available (~23s/boot,
   full diagnostic context, no GDB needed).
2. If the corrupted address (or a consistent relative position, e.g. "N bytes
   after a specific allocation site's return address") recurs across samples,
   that names the allocation whose NEIGHBOR is being corrupted — use
   `caller::dealloc_return_ip()`/similar on the malformed node's *neighbors* (the
   allocations immediately before/after it in the free-list address order) to
   identify who allocated what's now the victim.
3. If addresses are fully random with no pattern, this supports a genuine
   uninitialized/dangling POINTER somewhere (not a Layout/size bug) — the next
   angle would be a systematic audit of `MaybeUninit`/`mem::zeroed()` usage
   kernel-wide for anything that skips proper field initialization before being
   read/written by unrelated code, or a percpu/DMA buffer whose physical address
   aliases a live kalloc allocation (a mapping bug, not an allocator bug).
4. Audit `ContextAArch64::switch` (`crates/arch/hal-aarch64/`) for the same
   register-clobber hazard B1333 fixed on x86_64 — not yet checked, needed for
   ARM/x86 lockstep (CLAUDE.md Discipline #7).
5. Do NOT return to the hardware-watchpoint approach (exhausted, PR #3778) or
   loop >2-3 boots chasing one hypothesis without a specific question to answer.

### Non-determinism (established fact, don't re-litigate)
Confirmed repeatedly: identical binaries crash with DIFFERENT signatures on
different boots (6+ shapes seen this session alone). Never attribute a fix from
fewer than 3-5 boots. `debug-smp`'s Task stack-guard-byte canary does NOT
destabilize the fast repro (confirmed this session, contra an older suspicion).

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=1)
mcp__qemu__qemu_continue(...)   # times out at 120s internally, boot continues regardless
# wait ~25-35s, then qemu_serial() and grep for FAULT/PANIC/KALLOC/TASK-STACK-GUARD
```
Add `debug-smp` for the stack-guard-byte canary. `debug-heappoison` = same repro
but ~500s — **user has explicitly vetoed this for iteration**, one boot only if
truly needed. Always `qemu_list` + `qemu_stop` stale instances before starting a
new one. `nm -C <elf> | sort` + nearest-below-address lookup, and `addr2line -Cfi`
+ `objdump -d --start-address=... --stop-address=...` around a faulting `rip`,
are the two techniques that have found every lead this session — use them first,
before considering GDB (confirmed repeatedly unreliable post-fault/post-panic in
this environment).

### Housekeeping / prior fixes this session (all merged, don't re-investigate)
9 real cross-CPU UAF / logic bugs, none were THE root cause: B1325 (#3767)
corruption-probe fixes. B1326 (#3768) `fd_table`/`mm`/`exe_path` foreign-task
races. B1327/B1328 (#3770/#3772) ext4 `writeback_idxs` stale-frame UAF read.
B1329 (#3773) `parent_arc` race (genuine foreign writer). B1330 (#3774)
`cmdline`/`environ` torn-String reads. B1331 (#3776) `rlimits` foreign-task races.
`ctty` checked clean. `fpu_state` found-not-fixed (ptrace auth gap, own PR needed).
Not audited: `sigactions`/`seccomp_filters`/`posix_timers`/`arch_ctx`. B1332
(#3778) hw-watchpoint + `[TASK-DROP]` diagnostics. B1333 (#3779) ctxsw register-
clobber fix. C156/C157 (#3780/#3781) kalloc diagnostic-tag gaps — **this is what
made the `malformed-free-size` sample above possible; without it this session
would have seen the same silent panic as every prior session.** C158 (this
handoff) lowers `size_track.rs`'s threshold to 96B.

First command next session: 2-3 more `smp=1` fast-repro boots, grep for
`malformed-free-size`, compare addresses against this session's
`ffffffff81a6b7f8` — see "Concrete next steps" #1 above.
