## B1309-kalloc-uaf-diagnostics

### Headline
Continuing the zram/heap-corruption hunt (was `handoff.md`, folded in here — canonical
handoff lives in `state.md` only, no split source of truth). Bug still NOT fixed. Added
real diagnostic tooling this session and narrowed the corruption signature substantially
via 3 independent QEMU boots. Root cause (the actual corrupting call site) still unnamed.

### What's new this session (verified, on this branch)
- `crates/shared/kalloc/src/holes.rs` `try_merge`: added a last-4-visited `merge-trail`
  ring so a `merge-header-outside` panic always prints the corrupt node's immediate
  predecessors in address order — no more dump-cap guessing (the old `dump(256)` cap hid
  the real evidence in 2 of 3 boots this session because the corrupt node was further
  into the list than the cap reached).
- `crates/shared/kalloc/src/lib.rs`: added `periodic_validate` — every 64 alloc/dealloc
  ops (debug-heappoison only) runs a full free-list `validate()` and panics immediately
  on the first bad node, tightening the corruption-to-detection window from "one execve"
  to "~64 ops". Did NOT catch the corruption before the merge-walk did in boot #3 — worth
  rechecking if the interval needs to be smaller, or if corruption+reuse both happen
  within one window.
- Both compile clean against the real `oxide-kernel` targets (`cargo run -p xtask --
  kernel --arch x86_64 --features debug-boot,debug-heappoison,debug-pmm`).
- Kept from the prior (uncommitted) session, now on this branch: `HoleList::validate()`/
  `dump()`, PMM `kalloc_grow` mapcount/mapping asserts (`mm-pmm/src/boot.rs`), and the
  real `smoke::pmm::run` signature fix (`IrqGate` param) — all independently reviewed,
  real, keep regardless of the UAF outcome.

### The strongest new evidence (3 independent boots, `--features debug-boot,debug-heappoison,debug-pmm`)
Each boot hits `[KALLOC] merge-header-outside` / `[PANIC] kalloc back fragment invalid`
(or `kalloc invalid free`) once `systemd-zram-setup@zram0.service` starts — zram is still
just the first big allocator to walk into pre-existing corruption, not the cause.

- Boot 1: `node=ffffffff81aacbe0 node_size=4294967296(0x100000000) bad_next=0x1021994`
- Boot 2: `node=ffffffff8142d410 node_size=141718192128(0x20ff100000) bad_next=0xaaaaaa`
- Boot 3: `node=ffffffff819b0d10 node_size=0xeeeeeeeeffffffff bad_next=0xeeeeeeeeeeeeeeee`

**Boot 3 is the key clue.** Its raw 16 header bytes are `FF FF FF FF EE EE EE EE EE EE EE
EE EE EE EE EE` — i.e. still FULLY intact quarantine poison (`0xEE`, see
`crates/shared/kalloc/src/poison.rs`) except the first 4 bytes, which hold `0xFFFFFFFF`.
That is the signature of a **32-bit-wide write landing on an already-quarantined,
already-fully-poisoned block** — most likely a `u32` atomic decrementing past zero
(`0u32.wrapping_sub(1) == 0xFFFFFFFF`), NOT a generic `Arc<T>` strong-count UAF (Arc's
strong/weak counts are `AtomicUsize`, 8 bytes — a corrupting decrement there would smear
all 8 bytes, not exactly the leading 4).

This also explains why the existing poison/quarantine machinery
(`crates/shared/kalloc/src/poison.rs`) doesn't catch it: quarantine only re-verifies
poison *while a block sits in the ring*; the write happens **after** eviction, once the
block is a real (non-quarantined) hole back in the live free list — a gap neither the old
per-execve `validate()` checkpoint nor quarantine's `scan_window` covers. `try_merge`'s new
merge-trail helps narrow *where in the list* but not *who wrote it*.

Corrupted node address and garbage pattern differ every boot (matches memory
`gnome-blocker-refcount-uaf` — "symptom moves with layout"), so this is a real stray write
with a moving victim, not a single fixed bad instruction with a constant operand.

### Candidates worth auditing next (NOT yet confirmed — static grep only, not verified against real compiled layout)
Rust `repr(Rust)` structs have compiler-chosen field order/offsets, so "declared first
field" is NOT reliable evidence of offset 0 — needs a real `core::mem::offset_of!` check
or GDB `ptype`/DWARF query, not just source reading. Grepped for small, individually
heap-allocated (`Arc::new`/`Box::new`, not static-array-embedded) structs with a leading
`AtomicU32` refcount/counter whose decrement could run after the true last owner already
dropped its reference:
- `crates/kernel/vfs/src/mntns.rs` `Mountpoint { m_dentry: Arc<Dentry>, m_count: AtomicU32 }`
  — `get_mountpoint`/`put_mountpoint`, `fetch_add`/`fetch_sub` pair, size/shape plausible.
- `crates/kernel/modules/src/linux_configfs/core.rs:93` `refs: AtomicU32`.
- `crates/kernel/tty/src/core/tty.rs` `open_count: AtomicU32`.
- `crates/kernel/ext4/src/mount/core.rs` `txn_depth: AtomicU32`.
- RULED OUT: `mm-vmm/src/rmap.rs::PageRmap.mapcount` — lives embedded in a per-PFN static
  array (`pmm::setup::PageMeta`), never individually kalloc'd/freed, so it cannot be our
  victim (our victim is a real hole-list entry inside the 64MiB static BSS heap).

### Already ruled out (carried from prior session, still holds)
Today's 194-branch merge; VMA tree (`mm-vmm/src/tree.rs`); PMM alloc/free/rmap mechanics;
sched/task lifecycle (Task is the victim of a downstream fault, not the source); `debug-fwm`
peer-mapping backstop (enabled, never fired); kernel-image/static-heap PA overlap;
FPU/XSAVE buffer sizing.

### Downgraded from prior session
Prior handoff called `debug-leak-teardown` (leaking `as_teardown` frees) the "strongest
lead", pointing at `mm-pmm/src/user_as/teardown.rs`. Re-examined `as_teardown` this
session — its leaf-free path correctly routes through `rmap_aware_dec_and_maybe_free`, and
the PMM/`kalloc_grow` mapcount asserts (already on this branch) would catch a mis-freed
*mapped PMM frame* entering the heap via growth — but every corrupted node found this
session lives in the **original static 64MiB BSS heap**, which PMM/`kalloc_grow` never
touches at all. `debug-leak-teardown` delaying the crash is very likely a **timing/reuse-
order correlation**, not proof `as_teardown` is the corruptor. Don't re-chase teardown as
the primary lead without new evidence — it may still be a secondary/different bug worth
its own investigation, just not this one.

### Concrete next step
Do NOT do another boot-per-hypothesis cycle (repo policy + already did 3 this session).
1. Confirm real offsets: write a tiny hosted test using `core::mem::offset_of!` (or check
   via `gdb ptype`) for the 4 candidate structs above — keep only ones where the
   `AtomicU32` field is genuinely at byte offset 0.
2. For each survivor, audit every `fetch_sub`/decrement call site for a path that can run
   after the object's true final owner already dropped its last reference (double-drop,
   Weak-upgrade-after-last-strong-drop race, etc.) — this is exactly the shape of bug that
   would write `0xFFFFFFFF` into an already-freed block's first 4 bytes.
3. Only reach for a QEMU boot again once a specific call site is a real suspect, to
   confirm/deny with a targeted trace at that one site — not another blind full boot.

### Housekeeping
- Kill stale `qemu-system-x86_64` before starting new boots (`ps aux | grep qemu-system`).
- `/goal` hook active: "resolve all issues in handoff.md linux style no hacks no split
  truth" — still blocking on the unresolved UAF. `handoff.md` itself has been folded into
  this file and can be deleted; this file (`state.md`) is now the only handoff doc.
