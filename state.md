## FIRST-EVER resolved free_ip: the corrupted node's provenance names a real function

### The finding
Added a per-syscall-entry stack-guard checkpoint (B1323) and re-ran. This
boot hit the kalloc free-list class instead (not the stack-guard this
time — both classes are still independently reproducible). New and
different from every prior capture: `merge-corrupt-node-provenance` FIRED
for the first time with a real hit —
```
[KALLOC] seq=0 merge-header-outside node=ffffffff823b82b8 node_size=17216961135462248174 bad_next=eeeeeeeeeeeeeeee
[KALLOC] merge-corrupt-node-provenance base=ffffffff823b82b8 freed_size=4128 free_ip=0xffffffff80274c86
[KALLOC] corruption-probe addr=ffffffff823b82b8 pfn=00000007fff823b8 out-of-range
[PANIC] crates/shared/kalloc/src/holes.rs:618: kalloc back fragment invalid
```
Every prior quarantine-poison hit had `lookup_evicted` return nothing
(the corrupted address had never been through quarantine-then-eviction —
it was found live-in-quarantine directly). This one DID resolve:
`free_ip=0xffffffff80274c86` is a real return address. Resolved via `nm
-C` against the exact built ELF: falls inside
**`<alloc::raw_vec::RawVecInner>::finish_grow`** — i.e. the block was
freed by a `Vec`'s own internal reallocation-on-grow (the old backing
buffer, freed after copying into a larger one), NOT by any
subsystem-specific code. Size 4128 bytes is consistent with a modest
`Vec<u8>`/`Vec<T>` growth step.

### What this does and doesn't tell us
This corrupted node's address IS where the evicted (post-quarantine)
block was reinserted into the free list. Its bytes still read as pure
quarantine poison (`0xEE`) at the moment of discovery — meaning nothing
had legitimately carved/rewritten this address since eviction, which is
unremarkable on its own (freshly reinserted holes sit untouched until
something allocates from them). The open question this raises for next
session: does `HoleList::dealloc`'s reinsertion path for an
just-evicted block ever hand this address off to a NEIGHBOR's merge
(`try_merge` absorbing it into a physically-adjacent hole, updating the
neighbor's `size`/`next` but never touching THIS address's own bytes)
while some OTHER, earlier-established `.next` link still points directly
at it? That would explain exactly this shape: still-linked-in (reachable
by the active walk), but never actually re-written with a fresh header
because ownership of "the real hole here" moved to a neighbor. Also
notable: `corruption-probe` (B1322) fired but reported the address
"out-of-range" for a HHDM->PFN lookup — this address is in the static
kernel-image VA range, and the probe's `addr >= hhdm_offset` heuristic
apparently misclassifies it as HHDM space rather than correctly detecting
it as a static-heap/kernel-image VA (this kernel's `hhdm_offset` is
evidently a smaller value than the kernel image's own load VA, breaking
the simple `addr < hhdm` split assumed when B1322 was written) — a real,
minor bug in the probe itself, worth a follow-up fix, though it degrades
safely (a useless "out-of-range" message, not a wrong answer treated as
right).

### Concrete next step
1. Fix `corruption_probe`'s VA classification — it needs to positively
   identify "this address is inside the kernel image's own linked range"
   (comparing against the kernel's own `_start`/`_end` linker symbols or
   equivalent) rather than assuming anything `>= hhdm_offset` is HHDM
   space.
2. Audit `HoleList::dealloc`'s reinsertion path (`add_free_region` →
   `try_merge`) specifically for the "absorbed-into-neighbor, never
   individually rewritten" shape described above — this is now the most
   concrete mechanical hypothesis produced this session, backed by a real
   resolved free_ip instead of speculation.
3. `RawVecInner::finish_grow` being the free-side owner suggests casting
   a wider net: any `Vec`/`String` growth anywhere in the kernel is a
   candidate parent for the NEXT corrupted node's provenance too — worth
   checking whether future resolved `free_ip`s cluster on the same
   function (a systemic Vec-growth-adjacent bug) or scatter across many
   unrelated callers (favoring the neighbor-merge theory over anything
   Vec-specific).

## FIRST-EVER LIVE HIT of the ORIGINAL bug signature: "Task kernel-stack guard-canary wipe"

### What fired, verbatim
After B1322 (corruption-probe hook) merged, ran one more boot with
`debug-boot,debug-heappoison,sched/debug-stack-guard`. This time the
crash was NOT a kalloc free-list issue at all — it was
`Task::debug_check_canary`'s stack-guard-byte check, armed by B1314 and
never once successfully exercised before now (every earlier attempt this
session hit Eio before reaching this point, or hit a kalloc crash first):
```
[TASK-STACK-GUARD site=current_ref task=ffffffff81aa1ce8 tid=4299
  stack=ffffffff81ea18b0 stack_hi=ffffffff81ea58b0 sp=0 fp=0
  sp_in_stack=0 caller_line=103 offset=0 crossed_16k=0]
[PANIC] crates/kernel/sched/src/live/runqueue.rs:103: Task kernel stack underflow
[PANIC] halted
```
This is, verbatim, the ORIGINAL handoff.md crash signature ("a Task
kernel-stack guard-canary wipe") — the first time this exact class has
been directly, deliberately caught this session (or, per available
records, any prior session) instead of inferred from a downstream victim.

### Reading it correctly — `sp=0`/`fp=0` are a KNOWN x86_64 stub limitation, not new evidence
`debug_stack_pointer()`/`debug_frame_pointer()` on x86_64 are permanently-0
stubs (`methods.rs`, pre-existing, only aarch64 reads real registers via
inline asm) — so `sp=0 fp=0 sp_in_stack=0` here is EXPECTED on every
x86_64 hit of this check, not a sign the CPU's actual stack pointer is
corrupted. **The real signal is `offset=0`**: `debug_check_canary` scans
`stack[0..TASK_STACK_GUARD_BYTES]` for the first byte that isn't
`TASK_STACK_GUARD` (`0xA5`) and panics with that index as `offset`.
`offset=0` means the guard was wrong starting at byte 0 of the 32-byte
guard region — the WORST case (the whole guard is gone), not a
partial/edge hit.

### What this narrows
- Site is `current_ref()` — the task whose guard is wiped is the one the
  scheduler considers ACTIVELY RUNNING on this CPU right now, not a
  dormant/sleeping task discovered by some background scanner.
- The guard lives at the LOW end of the stack allocation
  (`stack[0..32]`); kernel stacks conventionally grow DOWNWARD from the
  high end, so under normal execution the guard region should be the
  LAST 32 bytes ever touched by legitimate stack usage. A write landing
  there either means (a) a genuine stack overflow (deep recursion / an
  oversized frame) ran this task's own SP all the way down past its
  watermark into the guard, or (b) an unrelated wild write — the SAME two
  possibilities the whole session's hunt has been choosing between for
  the kalloc-side victims. `crossed_16k=0` reports the 16 KiB watermark
  region (`TASK_STACK_WATERMARK_OFF`) as intact, which argues against a
  straightforward deep-recursion overflow (that would usually clobber the
  watermark on the way down before ever reaching the guard at the very
  bottom) — leaning toward (b), consistent with every other victim this
  session.
- `task`/`stack` addresses (`ffffffff81...`) are static-image kernel VAs,
  NOT the HHDM-mapped PMM-growth range B1322's corruption-probe hook
  resolves — so that hook did not (and structurally could not) fire here.
  Wiring an equivalent probe for static-heap addresses needs a real
  VA->PFN reverse map for the kernel image's own linked range, which does
  not exist yet (noted, not attempted this round).

### SECOND sample confirms it — and a new timing correlation
Ran one more boot, same features: hit the IDENTICAL signature again —
`task=ffffffff81dd61a8 tid=4309 ... offset=0 crossed_16k=0`, at
`[529.392]`, different addresses (moves with layout, as expected) but
otherwise byte-for-byte the same shape (guard wrong from byte 0,
watermark intact) as the first sample (`[485.855]`). 2/2 so far.

**New correlation, not yet explained**: BOTH samples' `[TASK-STACK-GUARD]`
line is the literal next line in the log after a `[KALLOC]
growth-registered` event (kalloc's heap-growth path successfully
completing) — same adjacency in both captures, at similar (~500-530s)
boot timestamps. This doesn't yet prove causation (could be pure timing:
both this check and kalloc growth are naturally busy in the same
general phase of a live desktop boot), but it's now a repeated pattern
worth treating as a real lead — kalloc's growth path AND the stack-guard
victim keep showing up adjacent in time to each other, alongside the
already-established kalloc-free-list victims. All three victim classes
(kalloc free list, kalloc growth registration, Task stack guard) cluster
in the same narrow window of every boot that gets this far. Next
session: check whether disabling/no-op'ing the grow hook temporarily (or
pre-growing a much larger static heap so growth never triggers) makes
either victim class stop appearing — a cheap, decisive test of whether
growth activity itself is a real trigger or just a coincident busy period.

### RULED OUT immediately — growth-timing correlation was coincidence
Ran that exact test: bumped `kalloc::STATIC_HEAP_SIZE` 64 MiB -> 512 MiB
(temporary, local-only, reverted after this test — not a real fix, just
removes growth pressure) and booted the same feature set. Result:
**`growth-registered` and `growth-request` both appear ZERO times in the
entire boot** — the 512 MiB static heap fully absorbed everything, kalloc
never once needed to call the grow hook. The Task stack-guard STILL
fired — a THIRD sample, identical shape (`offset=0 crossed_16k=0`,
`task=ffffffff81ac7788 tid=4298`), this time immediately after `[ZRAM-
SYSFS] disksize=1584398336` instead of a growth event. **Growth activity
is definitively not a cause** — the earlier "adjacent to
growth-registered" pattern in samples 1-2 was coincidental timing (both
things are naturally busy in the same late-boot phase), not causal. This
is now recorded as ruled out; don't re-test it.

### What 3/3 samples actually pin down
Every hit so far: `current_ref()`, `offset=0` (guard wrong from byte 0,
the worst case), `crossed_16k=0` (16 KiB watermark intact), tid in a
tight cluster (4298/4299/4309), timestamp in a tight cluster (~475-530s
across three differently-configured boots), and — across all three —
right after either zram sysfs activity or generic late-boot systemd
service churn, never anything more specific than "somewhere in this
~50-second late-boot window." This is now the SINGLE most reproducible
signal in the whole session (3/3, cheap, ~500s each, well-characterized)
— more reproducible than the kalloc free-list class, whose exact byte
pattern varies between hits. Next session should treat this as the
primary lead: narrow the ~475-530s window with a finer-grained boot
checkpoint sweep (call `debug_check_canary` explicitly, not just via
`current_ref`, at every major systemd-service-start boundary in that
window) to bisect which specific service/syscall is running at the exact
moment the guard gets wiped, rather than only catching it whenever
`current_ref()` happens to run next.

### Concrete next step
1. Get MORE samples of this exact check firing — now that it's proven it
   CAN catch something real, repeat boots with the same feature set are
   no longer a blind retry; they're exercising a confirmed-live detector.
   Watch specifically for whether `offset` is ever non-zero (a partial
   guard hit would narrow the write's shape further) and whether the
   SAME `tid`/task recurs.
2. This victim (a live Task's own kernel-stack guard) and the kalloc
   free-list victims are almost certainly the SAME underlying corruptor —
   the original handoff.md report named BOTH the zram/kalloc crash AND
   the stack-guard wipe as observed signatures of one bug. Any lead that
   explains one should be checked against the other.
3. Build the static-heap VA->PFN reverse map (or at minimum, a "does this
   VA fall within the kernel image's own linked range, and if so what's
   its corresponding PA via the kernel's load-bias" helper) so the
   corruption-probe hook can resolve `Task`/stack addresses too, not just
   HHDM ones — this specific victim class needs it more than the kalloc
   one did.

## TWO MORE REAL BUGS FOUND+FIXED (B1320, B1321) — the growth-register-failed mystery is FULLY RESOLVED

### What was actually happening (now proven, not guessed)
The `seq=` diagnostic (B1318) plus a fix attempt exposed TWO real,
independent self-deadlock bugs that had been silently swallowing panic
output all session (and very likely across prior sessions too):

1. **B1320**: `periodic_validate`'s `if let Some(bad) =
   self.inner.lock().holes.validate() { ... assert!(...) }` extends the
   Spinlock guard's lifetime across the WHOLE if-let body (Rust's
   if-let temporary-lifetime-extension) — so the assert panicked while
   still holding kalloc's own lock. Caught this live: a boot printed
   `seq=0 periodic-validate-failed bad_node=...` then went **completely
   silent forever** — no panic message, no halt banner, nothing, for
   15+ real seconds with zero further output. Fixed by binding the
   `Option<usize>` and letting the guard drop before the assert.
2. **B1321**: the x86_64 panic handler itself
   (`crates/arch/kernel-bin-x86_64/src/main.rs`) printed via
   `klog::write_raw`, which fans out to auxiliary console sinks (e.g. a
   framebuffer scroll) that CAN allocate. Any panic firing while the
   panicking call's own stack still holds `kalloc`'s Spinlock — which is
   the NORMAL, unavoidable shape for `HoleList::allocate_first_fit`'s own
   internal asserts (`kalloc back/front fragment invalid`), since they run
   nested inside `KAlloc::alloc`'s top-level `self.inner.lock()` by
   construction — would have this handler's own klog calls recurse into
   that SAME lock on the SAME CPU: another silent hang, zero panic text.
   Fixed by switching every print in the handler to
   `klog::write_primary_*`, the documented non-allocating route (ring
   buffer + primary console only, confirmed by reading its
   implementation — no allocation anywhere in that path).

### Live re-verification after both fixes: the "impossible sequence" is now just... normal
Re-ran the exact scenario that looked like two logically-impossible events
(a `growth-register-failed` with an unconditional `assert!` right after it,
followed by MORE `[KALLOC]` output and a DIFFERENT panic). With both fixes
in, the SAME event now prints cleanly and unambiguously:
```
[KALLOC] seq=0 merge-header-outside node=... bad_next=a5a5a5a5a5a5a5a5
[KALLOC] merge-trail ...
[KALLOC] seq=1 add-region-failed start=... usable=... end=...
[KALLOC] seq=2 growth-register-failed outside-owned-region
[PANIC] crates/shared/kalloc/src/lib.rs:558: kalloc grow region invalid
[PANIC] halted
```
**This fully resolves the state.md ambiguity item from the previous
round.** It was never two events — it was always ONE event
(`try_merge` discovers a corrupted node while `add_region` is trying to
register PMM growth → propagates `OutsideOwnedRegion` up through
`add_region` → `kalloc_grow` treats any growth-registration failure as
fatal and asserts). The assert always fired; the panic handler just
couldn't print because of bug #2 above. `growth-register-failed` is NOT
a precursor to the corruption — it's a SYMPTOM: growth only gets
triggered because normal allocation already failed, which happens
because the free list is ALREADY corrupted by this point. The two
earlier "seq=0 periodic-validate-failed" and "no growth-register-failed
at all" boots (this round, before these fixes) additionally prove
directly that growth interaction is not required to trigger the
underlying corruption — `try_merge`/`allocate_first_fit`'s ordinary carve
path finds it too, with or without a growth attempt nearby.

### The poison-byte signature just widened again: redzone (0xA5), not just quarantine (0xEE)
This live sample's `bad_next` was `0xa5a5a5a5a5a5a5a5` — `poison::
REDZONE_BYTE = 0xA5` (`poison.rs:30`), NOT quarantine's `0xEE`. This is a
FOURTH distinct value now observed at the same corruption site (garbage
real-data-looking bytes x2, quarantine poison, now redzone poison). This
generalizes the "BREAKTHROUGH LEAD" theory below: it's not specifically
about quarantine-vs-freelist double bookkeeping — it's that a stale
free-list `.next` link points at SOME address whose current true owner
varies (quarantine ring, redzone tail, a live reused allocation, or
whatever was there before any diagnostic ever touched it), and whatever
diagnostic fill (if any) is currently active at that address is what gets
reported as "the corruption." The redzone feature is itself new this
session (B1313) — worth specifically re-auditing `alloc_layout`/
`arm_redzone`'s carve-size math for an off-by-something that could place
a hole header on top of a redzone tail, though a static read of that math
this round did not find one (see below).

### Concrete next step (updated)
1. The hosted fuzz harnesses (B1317, B1319) still haven't reproduced this
   hosted despite covering single-threaded, multi-threaded, and grow-hook
   dimensions — worth adding a THIRD dimension: drive allocations that mix
   redzone-carved layouts with quarantine-eligible sizes in the SAME
   sequence (the fuzz harness's sizes already vary but never specifically
   targets the redzone-tail-adjacent-to-a-fresh-hole-header boundary the
   way it does for the quarantine boundary).
2. Diagnostics are now trustworthy end-to-end: `seq=` numbers plus a panic
   handler that can't silently swallow output. Next live capture should be
   read with full confidence in the printed order — no more guessing about
   whether an assert "really fired."
3. Re-audit `poison::alloc_layout`/`arm_redzone` and
   `HoleList::allocate_first_fit`'s front/back-pad math specifically for a
   redzone-tail placement bug, now that there's a concrete byte-value
   pointing at that feature specifically.

## BREAKTHROUGH LEAD — the "corrupted" node is kalloc's OWN quarantine poison

### The actual finding
Tightened `VALIDATE_INTERVAL` 64→8 (B1316) and re-ran. Periodic-validate
still didn't beat `try_merge` to it, BUT the third live sample's numbers
resolved something huge: `node_size=17216961135462248174` and
`bad_next=eeeeeeeeeeeeeeee` are, in hex, **both exactly
`0xEEEEEEEEEEEEEEEE`** — every byte of the `HoleHdr{size,next}` header is
`0xEE`. `poison::POISON_BYTE = 0xEE` (`crates/shared/kalloc/src/poison.rs:29`)
is kalloc's OWN quarantine fill: `quarantine()` writes `0xEE` across a
freed block's ENTIRE body and holds it in a ring, NOT in the free list,
until eviction. **The "corrupted" node in this sample is not corrupted by
some external wild write at all — it is a still-quarantined, still-poisoned
block that the free-list walk is treating as a live `HoleHdr`.** That is an
allocator-internal bug (a free-list node whose backing memory is
simultaneously/subsequently owned by the quarantine ring), not "a rogue
subsystem wrote to memory it doesn't own."

Rechecking the first two samples with this lens: `node_size` in hex was
`0x45ff100000` and `0x1ffff00001c2800` — NOT the `0xEE` pattern. This is
consistent with the SAME underlying defect (a stale free-list link to
memory that is no longer a legitimate free hole) observed at different
points in that memory's post-quarantine life: sample 3 caught it freshly
poisoned (pure `0xEE`); samples 1-2 likely caught it after that same
address had already been reused for a live allocation whose real data
partially/fully overwrote the poison — which is exactly why those two
looked like unrelated "real data" garbage with no fixed pattern, and why
the corrupted node's address moves between boots (whichever hole gets
fully consumed and never properly unlinked varies with allocation order).
This would unify ALL prior sessions' victims (Dentry `d_op`, zram Vec,
ext4 Vec, and now a raw quarantine slot) under ONE mechanism: something
leaves a stale `.next` reference to memory whose ownership has moved on,
and whatever that memory holds NOW (quarantine poison, or a live object)
is what gets reported as "the corrupted node."

### The immediate suspect, not yet pinned down
`HoleList::allocate_first_fit`'s carve/split path
(`crates/shared/kalloc/src/holes.rs:560-598`) unlinks the hole being
carved FIRST (`(*prev).next = (*cur_ptr).next`), then reinserts front/back
remnants as fresh headers only if `>= MIN_HOLE_SIZE` — a remnant smaller
than that is explicitly "leaked" (module's own doc comment, line ~7-9 and
~594-596) rather than reinserted. On paper this fully removes the old
header from the list either way, so where a STALE reference could survive
is not yet identified — this needs either a live backtrace (blocked, see
below) or a hosted proptest that deliberately drives alloc/free/quarantine
sequences designed to leave `front_pad`/`back_pad` right at the
`MIN_HOLE_SIZE` boundary and asserts the list never re-visits a byte range
that quarantine currently owns.

### A second, unexplained anomaly in the same window (not yet resolved)
All three samples show, immediately before the crash: `[KALLOC]
add-region-failed start=... usable=... end=...` then `[KALLOC]
growth-register-failed outside-owned-region`, against sequential 1 MiB
chunks at an HHDM-style address (`0xffff80007b400000`, then
`0xffff80007b500000` — a PMM-growth region, NOT the static kernel heap
where the corrupted node itself lives). That code path
(`crates/shared/kalloc/src/lib.rs:523-531`) has an UNCONDITIONAL
`assert!(false, "kalloc grow region invalid")` right after that print —
verified the string is compiled into the binary (`strings` on the built
ELF) and not local-only. Yet `"kalloc grow region invalid"` never appears
in any of the three captured logs; the actual, different panic (`kalloc
back fragment invalid`, holes.rs:592) fires instead, moments later, with
the SAME `merge-header-outside` diagnostic repeating verbatim beforehand.
Did not resolve why the first assert doesn't visibly fire — candidate
explanations not yet checked: serial-buffer truncation dropping earlier
output, two logically distinct `add_region` calls in flight, or the
harness's own serial capture being non-monotonic. Needs a live GDB
breakpoint on `lib.rs:530` to resolve for certain (blocked on the GDB
bridge issue, see below) — OR bisect by adding a distinguishing sequence
counter to each `[KALLOC]` log line so ordering is unambiguous even across
a possibly-lossy capture.

### Hosted fuzz harness written (B1317) — clean single-threaded run, real negative result
Wrote `HoleList::for_each_free` (test/hosted-only callback walker, since
this `#![no_std]` crate can't depend on `alloc` to return a `Vec`) plus
`tests::free_list_never_overlaps_a_live_quarantine_slot`: 20,000 rounds of
alloc/dealloc across 15 size/alignment combos chosen to straddle
`MIN_HOLE_ALIGN` boundaries (so carve leaves front/back remnants right at
the leaked-vs-kept edge), cross-checking after every single op that no
free-list address falls inside a currently-live `quarantine.lookup()`
slot. **Passed clean, zero violations.** This is a genuine negative result,
not a wasted effort: it rules out the SIMPLEST version of the "stale
free-list link into quarantine" theory — plain single-threaded carve/
free/quarantine cycling, no SMP, no PMM growth — as sufficient to trigger
it. Two real candidates remain for what's actually needed: (a) SMP/
concurrent access (this hosted harness is single-threaded; the live boots
that hit it all ran under real desktop multi-process/multi-thread load),
or (b) the PMM-growth-region interaction specifically (`kalloc_grow` /
`add_region`), which the fuzz harness never exercises (`fresh_heap` never
installs a grow hook) and which showed up suspiciously in EVERY live
sample right before the crash (see the growth-register-failed anomaly
above). Kept as a permanent regression test either way.

### Concrete next step (supersedes prior "keep auditing files" plan)
1. **Stop the file-by-file raw-pointer audit** — it's now well past the
   point of diminishing returns (11 files checked, 2 unrelated minor bugs
   found, zero hits on the actual corruptor).
2. Extend the B1317 hosted harness with (a) a real multi-threaded variant
   (std::thread over a shared `KAlloc`, if the lock types permit it hosted)
   pounding alloc/dealloc/quarantine from multiple threads concurrently,
   and (b) a grow-hook-backed heap so `add_region`'s interaction with an
   active free list + quarantine ring is exercised, not just the static
   fixed-size heap path. Either dimension the current harness didn't cover
   is now the most likely place the real trigger lives.
3. Resolve the growth-register-failed/assert-didn't-fire puzzle by adding
   a monotonic sequence number to every `[KALLOC]` diagnostic line — cheap,
   removes the ordering ambiguity outright.
4. Fix the qemu GDB bridge issue (or find a workaround) — a real live
   backtrace at the exact stale-link-creation site would resolve this
   outright instead of needing steps 2-3.

## Post-B1315 round — second corruption sample + wide audit, no new lead

### Second Eio-free boot sample (confirms the shape, not a new one)
Ran another boot after B1315 merged: same `kalloc back fragment invalid` /
`merge-header-outside` class at 498s (vs 513s last time). Different node
address (`ffffffff81ee16e0` vs `ffffffff81c924c0`) and DIFFERENT garbage in
the trashed header (`bad_next=0x02a300048d716c11`, not the `0xaaaaaa`-ish
value from the first sample) — two data points now agree: not a fixed
poison pattern, node address moves with layout, consistent with a live
object's real field data landing on the wrong address rather than a
"scribble with a constant" bug. Live GDB backtrace was attempted at the
panic site (breakpoint on `core::panicking::panic_fmt`) but the GDB MI
bridge wedged on both a pre-boot breakpoint insert (paused-at-entry, kernel
VA not yet mapped — no delete-breakpoint tool exists to recover, had to
restart the instance) and again on a post-boot `qemu_interrupt`/`qemu_break`
against a running instance (both timed out after 30s). Filed as
[[qemu-gdb-bridge-unresponsive-on-interrupt]] — treat live backtrace capture
on this kernel as unreliable; serial/klog forensics are the working method.

### Wide static audit this round — cleared, one unrelated leak, one unrelated race found
Audited (a background agent + directly, after the agent tooling hit two
transient 529-Overloaded failures and I finished the sched/ half myself):
`net/vsock/*.rs` (except `transaction.rs`, cleared earlier), `console`/
`vtconsole`/`fbcon`, `serialtty/lib.rs`, `syscalls/{056_clone,060_exit}`,
`ipc/live/futex/{wait,waitv,core,robust}.rs`, `sched/live/{ttwu,wait_list,
tick_deadline}.rs`. All either (a) a boot-once leak-forever `Arc::into_raw`/
`Box::into_raw` pattern (sound — the `&'static` claim backing every
dereference is true because nothing ever frees it), or (b) a same-CPU/
same-task `increment_strong_count`+`from_raw` idiom with no concurrent
freer, or (c) correctly lock-guarded removal-on-wake vs removal-on-timeout
(same shape already proven safe in futex). **No write-corruption defect
found in any of these** — this class of file is not where the bug lives.

Two REAL but UNRELATED findings, not the corruption bug (don't re-fix,
already noted for a future separate small PR):
- `crates/drivers/fbcon/src/font/runtime.rs:28-32` — `install()` stores a
  new `Font` into `ACTIVE: AtomicPtr<Font>` and never frees the previous
  one. A genuine leak (unbounded growth on repeated `set_font`), not a UAF
  — doesn't match the corruption signature (nothing is freed-then-written).
- `Task::exe_path` (`UnsafeCell<Option<String>>`, doc'd "single-mutator per
  13§5") is written only by the owning task itself (`prctl_set_mm.rs`,
  `spawn.rs` at fork) but READ from other CPUs with zero synchronization by
  `tick_deadline.rs:94` (timer-ISR deadline scanner, walks ALL live tasks)
  and the `diag/`+`trace.rs`+`proclink.rs` snapshot readers. A concurrent
  exec() on the owning task's CPU racing a timer-ISR read on another CPU is
  a genuine torn-read data race on a heap `String`'s (ptr,len,cap) triple.
  Ruled OUT as this session's corruptor specifically because every read
  site is a pure comparison/clone (`.contains()`, `.clone()`, `.as_deref()`)
  — a torn read can fault or misbehave on read, but cannot itself perform
  the WRITE that trashes an unrelated free-list header elsewhere. Real bug,
  wrong shape; worth a `Spinlock`/seqlock wrap in its own small PR later.

### Where this leaves the hunt
Ruled-out surface area is now very large: single-subsystem buggy frees
(zram/ext4/dentry), linear/adjacent overflow, the highest-suspicion raw-Arc
sites across sched/mm-pmm/net, and now vsock/console/serialtty/clone/exit/
futex/ttwu/wait_list/tick_deadline in full. Two corruption samples agree on
shape (free HoleList node header, non-fixed garbage, address moves with
layout) but neither fired any of the diagnostics wired up so far
(stack-guard canary, dcache d_op sanity, EvictHistory provenance, redzones).
The bug is real, reproducible (2/2 once Eio stopped blocking deep boots),
and still unnamed. Per the already-flagged highest-leverage remaining
options (unchanged from before this round): a hardware write-watchpoint
(tooling doesn't support it) or a real `-Zsanitizer=address` port (genuine
engineering investment, not attempted this session). Static per-file audits
have now covered most of the kernel's raw-pointer surface without a hit —
further blind file-by-file audits are low-probability; the next session
should either invest in the sanitizer or find a way to get a live backtrace
working (fix/route around the GDB bridge issue) so the ACTUAL writer's
identity, not just the victim's, can be captured.

## B1315-pmm-reserve-pfn-zero

### Headline — real, named, FIXED bug: PMM was handing out physical page 0
Found and fixed a genuine PMM defect that was also the root cause of the
"ext4 root mount Eio" blocker from the last few rounds (that blocker is
NOT feature-specific flakiness — it was misdiagnosed as such; see below).
With it fixed, got the FIRST 500+ second boot with `debug-stack-guard` +
`debug-heappoison` both active, and captured a fresh, live `kalloc back
fragment invalid` corruption — but the stack-guard canary and the dcache
`d_op` sanity check both stayed silent through it, so THIS occurrence is
neither the stack-guard-wipe class nor the live-Dentry class. `/goal`:
"resolve all issues in handoff.md linux style no hacks no split truth" —
still not met; the corrupting write site is still unnamed.

### The Eio root cause, actually named this time
`crates/kernel/mm-pmm/src/setup/boot_init.rs`'s `init_from_boot_info` built
its `UsableRegion` list straight from the firmware/bootloader memmap with
no reservation of physical page 0. On this boot's memmap, PFN 0 landed in
a `Usable` region and got handed out live by `alloc_raw_frame()` (which
sets refcount=0/mapcount=0 — indistinguishable from "still free" to the
allocator's own integrity checks).

That PA-0 frame was allocated as a virtio queue's `driver_pa` (avail ring)
for PCI `0:1.0` (the ROOT virtio-blk device — cap matches the 2.8G root
image). `crates/kernel/pci-boot/src/virtio_transport.rs:91` then does `if
... || q0.driver_pa == 0 { return None }` — PA 0 is treated as a null/
invalid sentinel THERE (and in several other spots: `require_queue`,
`frame_ptr` checks). So the root disk's queue setup silently "failed" (by
convention, not by real hardware failure), `init_blk()` bailed with no log
line at all, and the ROOT block device never registered. `by_serial
("oxide-root")` then missed and `kmain::rootfs::init` fell back to
`first_device()` — the much smaller `oxide-home` disk — and mounting THAT
as root ext4 correctly failed: `Eio`.

Confirmed via two identical 100%-reproducible boots (not flaky): both
showed exactly one `virtio-blk-modern` init log line (for `0:2.0`, cap_sec
matching the home image) despite TWO virtio-blk PCI functions doing full
virtqueue setup. `0:1.0`'s queue-0 trace showed `driver_pa=0000000000000000`
verbatim. This also explains the earlier apparent "debug-smp causes Eio"
and "debug-stack-guard also causes Eio" correlations from prior rounds —
both were coincidence; the real trigger is memmap-dependent (whether PFN 0
happens to land in a Usable region for that particular boot's firmware map),
not feature-dependent. That is now corrected in the record.

### The fix
`crates/kernel/mm-pmm/src/setup/boot_init.rs`: clamp `start_pfn` to at
least 1 when building each `UsableRegion`, matching Linux's unconditional
`memblock_reserve(0, PAGE_SIZE)` — PFN 0 must never enter the buddy free
list, full stop, regardless of what the firmware memmap claims. This is
the correct fix location and shape: one canonical place (PMM boot-time
region construction), not a scattered set of "treat PA 0 as invalid" patches
at each of the several call sites that already (accidentally) do that.
Hosted `cargo test -p pmm`: 123/123 pass. Both arches build clean.

### Boot-verified: Eio is gone
Two boots post-fix both sailed straight past the point that killed 100% of
prior attempts (was: guaranteed panic at ~6s). One ran 513 seconds deep into
real systemd/GNOME userspace (`upowerd`, `accounts-daemon`, `logind`,
`udisksd`, multiple real `EXECLOAD`/`elf-load` cycles) before hitting the
`kalloc back fragment invalid` corruption again — this is the deepest and
first Eio-free run of the corruption-hunt boots this session.

### This occurrence's forensics (new data point, not yet explained)
`[KALLOC] merge-header-outside node=ffffffff81c924c0 node_size=0x45ff100000
bad_next=0x00aaaaaa`, at `crates/shared/kalloc/src/holes.rs:592`. Checked
every diagnostic wired up so far against this specific event:
- `debug-stack-guard`'s canary (`Task::debug_check_canary`) — silent, never
  fired. Rules out this occurrence being the literal "Task kernel-stack
  guard-canary wipe" from the original handoff.md wording, at least for
  this instance of the bug.
- dcache `[DENTRY-BISECT]` periodic `d_op` sanity sweep — silent, never
  fired. Rules out the live-Dentry corruption class for this occurrence.
- `HoleList::lookup_evicted` (EvictHistory / free_ip provenance) — empty.
  This corrupted node was NOT a previously-freed/quarantined block; it was
  sitting live on the free list when its header got trashed. A third,
  distinct victim shape from the zram/ext4/Dentry victims found earlier.
- Redzone check (B1313) — not applicable here (redzones guard allocated
  blocks' tails, not free-list header memory), consistent with the earlier
  "not linear overflow" finding.
GDB bridge went unresponsive after the panic (`qemu_interrupt`/
`qemu_backtrace`/`qemu_regs` all timed out — 30s, no `*stopped`) so no live
backtrace of the actual corrupting call site was captured this round; only
the klog panic dump. Instance was stopped rather than burning more time
fighting a dead debug session (per "no repeated boot-per-hypothesis" spirit
— a wedged GDB bridge is a tooling problem, not a hypothesis to keep
re-testing blind).

### Session summary — what's confirmed vs still open
**Confirmed, real, independent fixes this session (all merged):**
- **B1309** (#3735): `HoleList::validate()`/`dump()`, `try_merge` merge-trail,
  `KAlloc::periodic_validate`, PMM `kalloc_grow` hardening asserts.
- **B1310** (#3736): fixed a confirmed self-deadlock in `poison.rs`. Added
  `HoleList::EvictHistory`.
- **B1311** (#3740): real x86_64 `free_ip` capture. `Dentry::drop` `d_op`
  canonical-address hardening.
- **B1312** (#3742): dcache-wide periodic `d_op` sanity sweep.
- **B1313** (#3744): wired dead redzone code; ruled out linear overflow.
- **B1314**: decoupled stack-guard canary check from `debug-smp`.
- **B1315** (this one): named + fixed the real PMM PFN-0 double-meaning bug;
  boot-verified Eio-free deep boots now possible; captured a third distinct
  corruption-victim shape (free HoleList node header, no provenance).

**What's been RULED OUT for the actual corruptor** (high confidence):
single-subsystem buggy frees (zram, ext4, dentries); linear/adjacent-neighbor
buffer overflow; `as_teardown`/PMM growth as primary cause; the highest-
suspicion `Arc::from_raw`/`into_raw` sites kernel-wide; today's stack-guard
canary and dcache d_op sweep for THIS SPECIFIC occurrence (still worth
running again — one clean miss isn't proof for every occurrence, only this
one); `debug-smp`/`debug-stack-guard` as causes of Eio (was the PMM bug).

**Still genuinely open**: the actual writer. Now with Eio fixed, deep
Eio-free boots are repeatable — the next session should get several more
data points on this corruption before concluding anything about which
diagnostic reliably catches it.

### Concrete next step
1. Re-run the same boot (`debug-boot,debug-heappoison,sched/debug-stack-guard`)
   now that Eio is fixed — it's no longer a blind retry, it's exercising a
   now-repeatable, deep, Eio-free path. Get 2-3 more corruption samples and
   check whether stack-guard/dentry-sanity/EvictHistory ever DO fire on a
   different occurrence (this round's one miss doesn't clear those checks
   for good).
2. Fix or route around the dead GDB bridge on panic — a live backtrace at
   the exact `try_merge` call site would likely name the actual caller
   immediately. Worth checking whether the panic path's `cli`+`hlt` loop can
   be given a debug int3 instead, or whether the gdbstub bridge itself needs
   a restart between the panic and the interrupt attempt.
3. `net/vsock/transaction.rs`, `console/*`, `serialtty/lib.rs`,
   `syscalls/{056_clone,060_exit}.rs`, `ipc/live/futex/{wait,waitv}.rs` —
   still only skimmed, not exhaustively audited.
4. If several more Eio-free boots all show the free-list-header victim shape
   (this round's) rather than the earlier Dentry/zram/ext4 shapes, that's a
   real pattern shift worth chasing on its own — could mean the earlier
   "victims found via EvictHistory" were themselves partly an artifact of
   Eio cutting boots short before this class had a chance to appear.
5. This bug has now resisted this session's extensive live+static effort AND
   multiple PRIOR sessions with dedicated agent audits (per
   `gnome-blocker-refcount-uaf` memory) — treat it as genuinely hard, not one
   grep or one boot away from resolution.

### Housekeeping
- Kill stale `qemu-system-x86_64` before new boots.
- Branches this session: B1309 (#3735), B1310 (#3736), B1311 (#3740),
  B1312 (#3742), B1313 (#3744), B1314 (#3746), B1315 (this one).
