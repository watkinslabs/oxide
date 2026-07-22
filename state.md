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

### Concrete next step (supersedes prior "keep auditing files" plan)
1. **Stop the file-by-file raw-pointer audit** — it's now well past the
   point of diminishing returns (11 files checked, 2 unrelated minor bugs
   found, zero hits on the actual corruptor).
2. Write a **hosted** (no boot) proptest/fuzz harness in
   `crates/shared/kalloc` that drives `alloc`/`dealloc`/quarantine-eviction
   sequences specifically targeting the `front_pad`/`back_pad <
   MIN_HOLE_SIZE` boundary in `allocate_first_fit`, PLUS sequences that
   force quarantine eviction right after a carve at the same address, and
   assert the free list never contains a node whose address the
   quarantine ring currently considers `live`. This is exactly the kind of
   test the project's own discipline calls for ("verify left" — hosted
   over booted) and could reproduce this in milliseconds instead of 500s
   boots.
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
