# Handoff — Goal 3 blocker UNIFIED: one heap/UAF refcount-corruption bug (NOT an SMP race)

Main has B706+B703/B704/B705 + nss fix merged. Goals 1 (console) + 2 (ext4) done.
**Goal 3 (visible gnome desktop): boot now runs the full D-Bus/logind/NetworkManager
service stack up to ~62-65s, then dies in a refcount abort BEFORE gnome-shell/gdm.**

## THE correction to the prior handoff (important)
Prior state.md said "smp=1 doesn't crash → the epoll #UD is an SMP race." **WRONG.**
This session proved smp=1 ALSO dies — a `[PANIC] alloc/src/sync.rs:3287` (the
`assert!(n <= MAX_REFCOUNT)` inside **`Weak::upgrade`**) at ~65.3s. smp=2 dies at
~55s with the epoll **`#UD`** (an `Arc<File>` strong-clone `lock incq; jle` abort).
Same root cause, two victims, both SMP configs. NOT an SMP-only race.

## Unified diagnosis (evidence-backed)
- A count > `isize::MAX` (MAX_REFCOUNT) is NOT reachable by legit over-cloning; it
  means the Arc/Weak inner pointer is reading a **freed-and-reused allocation** whose
  bytes now read as a huge refcount word. => **heap corruption / use-after-free.**
- Two DIFFERENT victim types (`Arc<File>` in epoll `scan_once`; a `Weak<_>` upgraded
  during `openat` — SuperBlock/inode/dentry) => it's clobbered memory landing on
  whatever refcount word, not one type's own refcount logic.
- Correlated with **fork-child** churn: `[USERIP ... tid=42xx lastsc=257 fork-child]`
  (257=openat) immediately precedes the abort; heavy fork+openat+epoll load (gnome
  session setup) triggers it. Not seen on lighter `lite` image.
- Strong prior-session correlation: [[qemu-vsock-cid-and-sigchld-reap]] flagged a
  SIGCHLD/zombie-reap stall (~13 zombies unreaped, suspect signalfd commit 2257275).
  Unreaped zombie `Arc<Task>`s + a reap-path refcount imbalance = this exact family.

## RULED OUT this session (read the code, refcount-correct)
- `vfs/src/fdtable/ops.rs` `fork_clone` (slot.clone() bumps each Arc<File>; bitmaps
  copied consistently), `get`, `close`, `dup*` — all balanced.
- `fs/src/epoll.rs` `scan_once` — `fdt.get(e.fd)` clone is correct; f is a fresh Arc.
- `sched/.../zombies.rs` `park_for_wait4`/`unpark_self_from_wait4` — increment_strong
  + from_raw pairing is balanced (+1 into WAITERS, -1 on swap_remove).
- `vfs/src/file/{lifetime,io}.rs` File Drop — no raw Arc juggling.

## PRIME suspects (unread / needs tooling)
1. Scheduler `Arc<Task>` round-trip: `sched/src/live/runqueue.rs` `Arc::into_raw(next)`
   on EVERY ctx switch + `from_raw(prev)`; interaction with fork (new task) + zombie
   reap + wait_list/futex `increment_strong_count`. Hottest path, touches every child.
2. signalfd/SIGCHLD reap (commit 2257275) x zombie `Arc<Task>` lifetime.
3. A plain buffer overrun somewhere writing past an alloc into an adjacent Arc header.

## NEXT — get EVIDENCE, do NOT ship a speculative patch (UAF patch w/o repro = hack)
Two viable tools (pick one; both avoid boot-per-hypothesis loops):
- **Poisoning allocator (boot ONCE):** add a debug-feature to the kernel heap/slab to
  fill freed blocks with 0xEE + quarantine (delay reuse) + record free-site backtrace.
  A UAF read then deterministically reads 0xEEEE… (huge count) → same abort, but now
  with the FREE site captured. Boot the gnome image once, read the free backtrace.
- **loom model:** model runqueue switch + park_for_wait4 + reap + fork concurrency for
  the Task-Arc into_raw/from_raw imbalance.
Then fix the real lifecycle bug; hosted-verify; ONE boot to confirm gnome-shell/gdm.

## First commands next session
1. `cd /home/nd/oxide/kernel && git log --oneline -3`
2. Repro (fresh, smp=1): `mcp__qemu__qemu_start arch=x86_64 features=debug-boot,debug-wakelat smp=1 mem=4G paused=false`
   → run_until 'PANIC|FAULT' — fires ~65s (smp=1) / ~55s (smp=2). It IS the gnome image.
3. Read `sched/src/live/runqueue.rs` (into_raw/from_raw) + add the poison-alloc feature.

## Gotchas
- gdb `qemu_interrupt` will NOT preempt the `cli;hlt` panic-halt (times out) — read the
  crash from serial (PANIC file:line), not the backtrace.
- run_until buffers hit the token cap; parse the saved tool-result file with python.
- NEVER `git add -A`. No boot-per-hypothesis loops [[no-repeated-long-boots]].
- live-gnome→gnome image (2.8GB); backups ../images/out/*.premerge.bak.
