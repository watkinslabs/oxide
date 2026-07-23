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

### `crates/kernel/vfs/src/dcache/hash.rs` read in full — matches the disassembly
The dcache hashtable (`DentryHashTable`, `hash.rs`) is a fixed 256-bucket array;
each bucket is `Spinlock<Vec<Arc<Dentry>>, DentryClass>` + a seqcount. `insert`/
`remove` correctly take the lock for every mutation; `lookup_rcu`'s FIRST line
(`hash.rs:100`) is `let (s1, snap) = { let g = b.entries.lock(); (b.seq.load(...),
g.clone()) };` — cloning the WHOLE bucket `Vec<Arc<Dentry>>` under lock. This is
an exact structural match for the disassembly at the crash site: a loop reading
each element, `lock incq`-ing its refcount, writing it into a new buffer — i.e.
`Vec<Arc<Dentry>>::clone()`. **The NULL was very likely a corrupted slot inside
the bucket's own small heap-allocated `Vec<Arc<Dentry>>` buffer** — a zero write
landing inside it, same mechanism as the `HoleHdr`/`Task`-canary/`Dentry.sb`
samples, just a different (and very small — likely a handful of pointers, well
under even the 96B `size_track` threshold) victim allocation.

**Did not lower `size_track`'s threshold further this session** — `insert`/
`remove` (`Vec::push`/`Vec::retain`) are a VERY hot path (every dcache lookup
miss + every dentry create/destroy), so tracking allocations that small risks
exactly the timing distortion this diagnostic exists to avoid (unlike
`debug-heappoison`, which already pays that cost deliberately). This needs a
considered decision next session, not a reflexive lower-and-boot: either (a)
accept the timing cost for one investigative boot (single-shot, not iteration —
matches the user's existing carve-out for `debug-heappoison`), or (b) instrument
`hash.rs`'s `insert`/`remove`/`lookup_rcu` directly (e.g. a guard-byte pattern on
each bucket's Vec, checked on every access) instead of using the generic
allocator-level tracker. `entries.lock()` synchronization itself looks correct on
inspection (every mutation and every read takes the bucket lock) — and this
reproduces at `smp=1` (no second CPU to race with), so if this IS the mechanism,
it's a single-threaded external write into the bucket Vec's memory, not a dcache
locking bug — read `insert`/`remove` again for a **single-threaded** logic error
(e.g. a stale `Vec` capacity/pointer used after a `push` that reallocated) before
assuming "wild external write" again.

### Ran 2 more boots chasing address recurrence — NO recurrence, but a THIRD dcache hit
Two follow-up `smp=1` boots after the sample above did NOT reproduce the exact
`malformed-free-size` tag (2 more entirely distinct crash shapes — 8th and 9th
this session, confirming addresses are NOT fixed/recurring — rules out "one
specific allocation site always corrupts the same neighbor"). But one of the two
faulted inside **`vfs::dcache::alloc::d_lookup_reval`** (`crates/kernel/vfs/src/
dcache/alloc.rs:78`) — `lock incq (%rdx)` where `rdx`, loaded from an array
being iterated (`mov (%r14,%rax,1),%rdx`), was NULL. This is a bulk-copy/refcount-
bump loop over what should be a list of valid `Arc<Dentry>`-shaped pointers (note:
`nm`'s nearest-symbol resolution may be pointing at an inlined callee of
`d_lookup_reval`, e.g. `DENTRY_HASHTABLE.lookup_locked`/`lookup_rcu` — read
`crates/kernel/vfs/src/dcache/alloc.rs` and `crates/kernel/vfs/src/dcache.rs`'s
hashtable bucket-walk code to find the exact loop, don't assume it's literally
inside `d_lookup_reval`'s own body).

**This is now the strongest converging signal of the whole hunt: 3 of 9 distinct
crash samples this session (drop_slow x2 + this one) all hit dcache/Dentry code
specifically, more than any other subsystem** — each finding NULL where a live
`Arc<Dentry>`-shaped pointer was structurally guaranteed. Combined with the
`Dentry.sb` construction-path audit (all clean, see above), this points at
**dcache's own bucket/hashtable machinery, or a Dentry's `children`
`BTreeMap<String, Arc<Dentry>>`, having a lifetime/removal bug** — something
leaves a stale slot (not properly removed on dentry teardown, or removed with a
race) that later gets read/incremented as if still valid.

### Concrete next steps (priority order)
1. **Read `crates/kernel/vfs/src/dcache.rs` (the hashtable) and `dcache/alloc.rs`
   end-to-end**, focusing on: (a) `DENTRY_HASHTABLE.lookup_rcu`/`lookup_locked`'s
   exact bucket-walk loop (matches the disassembly above), (b) every place a
   dentry is REMOVED from the hashtable/bucket (on `dentry_kill`/rename/prune) —
   check ordering against `Arc`/refcount teardown, same shape as the ALREADY-
   FIXED `switched_from->on_cpu` bug (write-before-drop ordering, see
   `switch.rs`'s `oxide_finish_task_switch` comment for the reference pattern).
2. If the hashtable itself is clean, check `Dentry.children:
   RwLock<BTreeMap<String, Arc<Dentry>>>` (`dentry.rs:100`) removal paths for the
   same shape — a child removed from ITS OWN parent's map while something else
   still walks a snapshot/clone of that map.
3. `malformed-free-size` addresses do NOT recur — don't keep chasing address
   identity; the next signal to chase is dcache's data-structure lifetime, above.
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

### Housekeeping (all merged, don't re-investigate; SHAs/details in git log)
9 real cross-CPU UAF/logic bugs found+fixed, none were the root cause: B1325-1331
(Task field foreign-access races: `fd_table`/`mm`/`exe_path`/`parent_arc`/
`cmdline`/`environ`/`rlimits`; ext4 `writeback_idxs` UAF; corruption-probe fixes).
`ctty` checked clean; `fpu_state` found-not-fixed (ptrace auth gap, own PR
needed); `sigactions`/`seccomp_filters`/`posix_timers`/`arch_ctx` not audited.
B1332 hw-watchpoint + `[TASK-DROP]` diagnostics (leads exhausted, kept). B1333
ctxsw register-clobber fix (real, see above). C156-C158: kalloc diagnostic-tag
gaps + `size_track.rs` threshold — **C156/C157 is what made the
`malformed-free-size` sample above possible; without it this session would have
seen the same silent panic as every prior session.**

First command next session: `Read crates/kernel/vfs/src/dcache.rs` and
`crates/kernel/vfs/src/dcache/alloc.rs` end-to-end — see "Concrete next steps"
#1 above. No more boots needed to start this one; it's a pure code-reading task.
