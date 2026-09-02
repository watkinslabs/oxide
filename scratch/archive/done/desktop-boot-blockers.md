# Desktop boot blockers — status 2026-07-08

Goal: boot the glibc GNOME image to a visible gdm greeter. Chain of blockers,
each fixed reveals the next. Boots done on a CLEAN host (codex agent paused).

## Status legend
FIXED = merged. VERIFIED = boot-confirmed, branch not merged. OPEN = not fixed.

| # | Blocker | Status | Branch / PR |
|---|---------|--------|-------------|
| 1 | qemu hardcoded `vhost-vsock guest-cid=3` (host-global) → parallel Codex agent's boot-loop wedged EVERY boot at launch | **FIXED** | PR #2848 merged (`buildns::qemu_vsock_cid`, per-launch CID+ports) |
| 2 | systemd-journal-flush timeout | **not a bug** | pure codex CONTENTION; passes on a clean host |
| 3 | SIGCHLD zombie-reap wedge: init parks in epoll_wait, exit_group children pile up unreaped (~13), boot freezes ~10s | **VERIFIED FIXED** | `B661-signalfd-sigchld-reap` (signalfd poll/read consult `has_zombies`). Proof: init reaps went 0→15, boot advances past the wedge |
| 4 | **`systemd-journal-flush` HANGS ~90s then times out** (NOT slow I/O — disproven) | **OPEN** ← desktop wall | journald ↔ ext4 write/mmap livelock |

## Blocker #4 — CORRECTED (instrumented boot 2026-07-08)
Earlier theory "demand-paging/ext4 reads are ~200× slow" is **DISPROVEN**. I
instrumented the virtio-blk completion wait (`wait_for_completion`, `[BLKSLOW]`
if an I/O > 20ms): across a whole boot only **ONE** slow I/O (a single 43ms
read). Block I/O — read AND write — is FAST. So it is NOT paging/read slowness.

What actually happens: `systemd-journal-flush.service` starts (~[9s]), its
process is exec'd (~[10.3s]), then **HANGS for ~90s** doing NO block I/O, until
systemd's `service_dispatch_timer` fires `start operation timed out. Terminating`
(SIGTERM, status=15) at ~[99s]. The multi-minute boot (271s/552s earlier) is
these ~90s service HANG-then-timeout cycles stacking, NOT slow reads.

So #4 = the ORIGINAL journald problem (see [[journald-empty-ext4-writeback]]):
journald's flush to /var/log/journal on ext4 **livelocks / blocks on a non-I/O
op** (mmap/msync writeback loop, a lock, or an ext4 metadata op that spins). B653
(fault-fill lock) + B655 (unwritten convert) were merged but journald still hangs.

NEXT (decisive): a **task dump DURING the hang** to get journal-flush's stuck
`last_syscall` + state. `OXIDE_SMP=1 ./tools/boot-smoke.sh x86 55` (unique
SMOKE_KEEP_LOG) — the 55s timeout fires WHILE journal-flush is hung (it hangs
[10..99s]) → boot-smoke injects sysrq `<NUL>t` → task dump shows the stuck
syscall. That names the exact op (msync? fsync? a futex? an ext4 ioctl?) to fix.
Do NOT re-chase "slow I/O" — it's fast.

## #4 — sub-hypotheses RULED OUT (hosted, no boot)
- Slow block I/O: DISPROVEN (instrumented `wait_for_completion` — 1 slow I/O all boot).
- Framecache writeback livelock: NO — `framecache.rs writeback()`/`writeback_idxs`
  process the dirty set ONCE and return (re-dirty on failure is for a LATER call,
  no internal loop). `msync`/`fsync` can't spin here.
- `kill`/signal doesn't wake the target: NO — `syscalls/062_kill.rs sys_kill`
  calls `sched::live::wake_if_sleeping(&t)` after setting the pending bit, which
  routes through `try_to_wake_up` (wakes an epoll_wait-parked target).
- journald IS reached: init reaps work (B661). Task dump during the hang shows
  processes in epoll_wait/ppoll/pselect6 + transient exit_group zombies; comms
  are unresolved ("fork-child"), so journald's exact stuck syscall is NOT named.

## UPDATE 2026-07-08 (after B661 + rt_sigqueue wake fix)
Two more real fixes landed and boot-verified to help:
- **B661** signalfd SIGCHLD-reap (verified: init reaps 0→15).
- **rt_sigqueue wake** (`signal_common.rs rt_sigqueue_to` now `wake_if_sleeping`):
  RT signal to an epoll-parked task now wakes it. Real bug (matched sys_kill etc.).
Result: a clean boot now has **exactly ONE service timeout — systemd-journal-flush**
— everything else runs; early targets (getty/cryptsetup/…) reached at [6.5s]. So
the desktop is ONE isolated blocker away: journald's FLUSH OPERATION hangs (~90s).
Note rt_sigqueue was NOT journal-flush's cause (still hangs) — journalctl --flush
likely uses plain kill (which already woke); the hang is the flush WRITE itself.

Strongest lead (memory [[journald-empty-ext4-writeback]]): journald finds the
PREBUILT /var/log/journal/*/system.journal "corrupted / uncleanly shut down" and
hangs RENAMING+replacing it (an ext4 rename/create/fallocate on the journal file
never returns). CHEAP FIX TO TRY FIRST: ship an EMPTY /var/log/journal in the
image (images repo, needs sudo) → journald makes a fresh file, no rename hang.

## #4 — DECISIVE next step (needs the debug shell, not code-reading)
The image has `systemd.debug_shell=ttyS0` (passwordless root serial shell). Boot,
and while journal-flush is hung (window [10..99s]) read journald's stuck syscall:
`ps aux | grep journald` → `cat /proc/<jpid>/syscall` and `/proc/<jpid>/stack`,
and the flush target `cat /proc/<flushpid>/syscall`. That NAMES the blocked op
(msync? fsync? a futex? a rename/link on ext4? a poll on a socket to journald?).
Then fix that one op. Prior sessions' lead: journald writes 0 entries to
`/var/log/journal` (see [[journald-empty-ext4-writeback]]) — likely the flush
write to a NEW system.journal blocks. Cheap first try: ship an EMPTY
`/var/log/journal` in the image (images repo) so journald makes a fresh file.

## OLD (disproven) #4 detail — kept for the record
Clean-host boot (SMP=1, no contention): **552s to reach `local-fs.target`**
(normally ~2-3s). Time is NOT uniform — it's a few HUGE discrete stalls:
- **271s stall** right after `[10.4s] elf-load: interp place ok` → the next
  output is `systemd-tmpfiles-setup-dev` doing its first `mknod` at [281s].
- **241s stall** after a later `wait4 reap` (another service's exec).
- 30s / 24s / 13s stalls, all after `elf-load: interp place ok` or a reap.

Interpretation: each dynamically-linked service, after the kernel places
`/lib64/ld-linux-x86-64.so.2`, spends MINUTES before it runs — the dynamic
linker demand-paging the binary's shared libraries (libc, libsystemd, …). Every
`.so` page fault → an ext4 read. So loading one binary = hundreds/thousands of
individual slow page-fault reads.

CONFIRMED root-cause lead (code-read):
- **`mount/io.rs:31 read_byte_range` goes STRAIGHT to the block device
  (`dev.submit_sync`) with ZERO caching** — for data blocks AND extent-tree
  interior nodes. `resolve_pblock` re-walks the extent tree on every
  `read_file_block`, so every page fault while loading a `.so` re-reads the SAME
  interior extent nodes + GDT + superblock from disk. A `block/src/pagecache.rs`
  exists but the ext4 read path BYPASSES it. Loading a multi-MB library =
  O(faults × tree-depth) redundant uncached metadata reads.
  FIX: route ext4 metadata/data reads through the block pagecache (or a small
  per-inode extent-map cache like Linux `extent_status`), so a re-read is a
  cache hit. Highest-ROI.
- Also add readahead on file-backed mmap faults (Linux clusters faults + async
  readahead) so a `.so` loads in a few batched reads, not 512 single-page ones.
- Possible per-request virtio-blk `submit_sync` latency — measure a single 4K
  read; if it's ~100ms not ~1ms, the driver's completion poll is the sink.
- A writeback/read livelock in the framecache (see [[journald-empty-ext4-writeback]]).

NEXT: hosted harness — mmap a multi-MB file from an ext4 image, fault every page,
count block reads + measure; confirm it's O(pages) slow round-trips with no
readahead. Then add readahead / batched extent reads. THEN one boot to confirm
graphical.target.

## Ready but unmerged
- ext4 stack `B656`–`B660` (A1 mtime, A2 s_state, A4 extent-bound, A3 rmdir, B3
  msync) — hosted-tested, both arches build. See `scratch/ext4fix.md`.
- `B661` SIGCHLD reap — verified, builds. Push after a clean boot confirms.

## Boot hygiene (learned painfully this session)
- `pkill -9 qemu` WORKS here. But ONE boot at a time — overlapping make/boot runs
  collide on `target/builds/default/*.img` ("Is another process using the image").
- Don't `pkill cargo` mid-build (corrupts the build → make exit 2).
- The qemu MCP path stalls at SeaBIOS even clean — use `make qemu-x86` /
  boot-smoke. Capture serial to your OWN log path; boot-smoke rm's its /tmp log.
