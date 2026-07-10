# GNOME-boot campaign ledger

Goal: boot live-GNOME, fixing every kernel system on the path 100% Linux-compat,
no hacks/stubs. Every item ships with a hosted smoke test / harness (fast path);
boot only to verify. Source: scratch/kernel-audit2.md.

Rule: fix the first failing boot contract before chasing subsystem completeness.

| # | Item (audit ref) | Status | Branch | Harness |
|---|---|---|---|---|
| 1 | tmpfiles-dev-early 249s stall = missed AF_UNIX targeted wake (§2.5) | IN-PROGRESS | B700? | net af_unix wake harness |
| 2 | udev/devfs/sysfs uevents + /dev nodes (§2.2) | TODO | | |
| 3 | systemd mount contract (§2.3) | TODO | | |
| 4 | cgroup v2 unified (§2.4) | TODO | | |
| 5 | AF_UNIX/netlink/epoll/D-Bus reliability (§2.5) | TODO | | |
| 6 | procfs/sysfs basics (§2.6) | TODO | | |
| 7 | DRM/KMS + fb (§3.1) | TODO | | |
| 8 | input/evdev (§3.2) | TODO | | |
| 9 | TTY/PTY/VT/logind session (§3.3) | TODO | | |
| 10 | swap (swapfile-on-ext4) (§3.4) | TODO | | |
| 11 | basic net (lo + one virtio-net) (§3.5) | TODO | | |

## Done this session
- ext4 100% complete (14 lanes) + B699 op_lock/flush livelock fix (merged, main).
  Boot now clears the ext4 livelock; hwdb finishes ~55s (was hard-hang).

## Item 1 — ROOT CAUSE FOUND: slow per-op virtio-blk I/O (~2ms/op)

Diagnosis chain (4 diagnostic boots + code trace), DEFINITIVE:
- tmpfiles-setup-dev-early "249s stall" is a symptom, not the bug. debug-dbus trace:
  userdb varlink replies are FAST (ms); the ~15s cadence is between query bursts.
- debug-taskdump (t=20/43/63s): **systemd-hwdb (tid 39) blocked in ONE fsync (nr#74)
  for ~50s** — nsysc frozen 20916 across 23s, only ~245ms CPU => I/O-blocked, not CPU.
  Then exits. This is [[hwdb-blocker-ext4-writeback-commits]].
- /proc/interrupts: LOC timer ticks ~915/s (periodic tick fine; NOT an idle-tick bug).
- I/O runs at ~87 ops/s equivalent; hwdb's 13.5MB fresh-file write+fsync = ~27k
  single-block (4KB) ops. Under KVM that should be <1s; 50s => **~2ms per block op**.

Ruled OUT (code-verified):
- Data is ALREADY data=ordered: write_file_block (blocks.rs:174) and
  insert_logical_block (append.rs:71) write data DIRECT via write_byte_range, NOT
  journaled. So it's not data-journaling amplification.
- Writeback amplification is bounded: tests/writeback_amp_image passes (~8 ops/page).
- Scheduler deferred-wake path (ttwu_deferred -> wake_list -> schedule drain) is sound;
  idle anchor loop (smoke/elf.rs:152) drains it each tick. park_with_deadline stamps
  wakeup_deadline_ns; tick_wake_expired (100ms throttle) delivers. epoll/poll/accept all
  have 20ms safety-net rescans.

REMAINING UNKNOWN (needs ONE targeted measurement, not a blind fix):
Why ~2ms per virtio-blk op? Submit path: acquire_turn (single-inflight serialize) ->
submit -> spin IO_SPIN_BUDGET(200k) -> park_blk (IRQ wake via wake_completions).
Suspects: (a) parks every op + slow park/wake round-trip; (b) MSI-X not firing
(boot enum logged virtio-blk msi_fires=0) so completion only caught by spin/timeout;
(c) acquire_turn thundering-herd under concurrent I/O (hwdb + userdb nss reads + tmpfiles).
STRONGEST HYPOTHESIS: driver is SINGLE-INFLIGHT — acquire_turn (engine.rs:205)
serializes EVERY block op (one `busy` turn). Linux keeps queue-depth 128+ I/Os in
flight so 27k ops pipeline; ours pays the full host round-trip SERIALLY per op =>
27k x ~2ms = ~50s. Real fix = multi-inflight virtio-blk queue (descriptor ring
already sized 256) OR coalesce contiguous writeback blocks into multi-block
requests. Both real, non-hack; need careful test (concurrent I/O, e2fsck, boot).
NEXT: instrument wait_for_completion (drv-virtio-blk engine.rs:175) to count
parks-vs-spin-hits + measure wall/op, ONE boot. Then implement multi-inflight or
request coalescing (data blocks are already direct-to-target, so coalescing the
write_byte_range calls in insert_logical_block/writeback is the smaller change).
Fast-path harness idea: hosted StatsDev already counts ops; add a large-write+fsync
op-count assertion (existing writeback_amp is the template).

## Landed this session
- B699 (#2916): ext4 op_lock held across dev.flush livelock — deferred batch commit.
- B700 (#2917): race-free AF_UNIX accept park + accept/TCP 20ms safety-net rescan.
- B701 (#2919): write_byte_range skipped the RMW pre-read for block-aligned
  full-block writes — hwdb's 13.5MB fresh file was all full-block writes, so every
  data block did a dead pre-read (~3400 useless serialized reads). Measured
  block-reads 53->13 on writeback_amp; e2fsck clean. ~HALVES hwdb fsync I/O.

## NEXT LEVER (high-impact, mechanism-verified) — coalesce data writes to 128KB
virtio-blk BOUNCE_DATA_BYTES = 128 KiB (drivers/virtio/src/blk.rs:42) → ONE virtio
op moves 32×4KB blocks. But ext4 writes data per-4KB-block: write_at_inner
(extent_rw/write.rs) loops per logical block calling write_file_block /
insert_logical_block → one write_byte_range (1 block) each. hwdb 13.5MB = ~3456
single-block ops; coalescing contiguous PHYSICAL runs into 128KB write_byte_range
calls = ~108 ops (32× fewer serialized). write_byte_range already issues one
multi-block virtio request (submit handles data_len up to 128KB). FIX: in
write_at_inner, after mapping logical→physical for the range, group contiguous
physical blocks and issue one write_byte_range per run (data blocks are already
direct-to-target so this is a pure data-path batching change; metadata journal path
unchanged). Validate: extend writeback_amp to assert ops/page drops + e2fsck +
concurrent-write stress, then boot. Risk: rootfs data-path — test thoroughly.

B702 (#2921): landed — coalesce contiguous data writes into 128KB virtio ops
(write_at_inner defers per-block writes → flush_pending_data_writes; extent mapped
WRITTEN, data written before batch commit = data=ordered). writeback_amp 4.3→1.3
ops/page; read-back verified; e2fsck clean; 235 tests pass.

BOOT-VERIFIED (debug-taskdump, main+B702): hwdb fsync 50s → ~30s (in fsync at t=22,
exited by t=42). IMPROVED but boot still does NOT reach gdm. Root now isolated
DEFINITIVELY to **per-op virtio-blk I/O latency on SMALL scattered I/O** that can't
coalesce: tmpfiles/userwork still crawl (userdb nss /etc/group reads, small-file
reads), each blocking-read paying the single-inflight round-trip. hwdb's large
sequential write coalesced; the many small reads did not.

## ★ MAJOR CORRECTION 2026-07-10 (BLKLAT probe, measured then reverted)
virtio-blk I/O is **~16µs/op and NEVER parks** (`[BLKLAT] ops=262144 parked=12
avg_us=15`). The per-op-latency / multi-inflight theory below is WRONG — I/O is fast.
TWO separate problems:
 (A) I/O VOLUME: ~262k block ops in the first ~11s (t5–16) from ext4 metadata
     amplification. B701/B702 reduce it; more possible (cache metadata reads).
 (B) **THE 249s BLOCKER**: block I/O STOPS at t≈16s but boot keeps stalling. The
     tmpfiles-setup-dev-early 249s is a phase-2 **AF_UNIX/varlink WAKE MISS** (15s
     cadence — a userspace varlink timeout breaks a tmpfiles↔userwork mutual block).
     NOT I/O, NOT CPU, NOT the scheduler tick. B700 fixed the accept race but the
     cadence persists → another missed wake in the varlink round-trip.
NEXT (do this, ignore multi-inflight): instrument the AF_UNIX round-trip — add a
trace to read_unix_stream_blocking (park/wake, deadline), sys_accept, and the userdbd
worker-spawn/SIGCHLD path, keyed to the userdb sockets. One boot shows WHO parks, who
should wake it, and what fires at the 15s mark. Static analysis says every wake
"should" fire (register_subs/notify_subs share sock.poll_subs; ppoll has the safety
net; blocking-read wake is race-free) — so only a live trace will catch the miss.
Candidate: blocking-read reply wake to tmpfiles (deadline 0, NO safety net) — if that
one targeted wake is dropped, tmpfiles stalls until the 15s varlink timeout.

## (SUPERSEDED by the correction above) virtio-blk per-op latency / multi-inflight
Every block op serializes through acquire_turn + one bounce buffer + descriptor 0
(engine.rs:107,127,205). Under KVM each op pays the full host round-trip SERIALLY;
Linux hides this with queue-depth 128+. Small scattered reads (nss, dyld, config)
dominate sysinit and can't be coalesced, so they bottleneck at ~1-2ms/op.
Two candidate fixes:
 1. VERIFY MSI completion IRQ actually fires (enum logged msi_fires=0; MSI-X table
    entries masked). If completions rely on the 200k spin (IO_SPIN_BUDGET ≈ 1.3ms)
    instead of a prompt IRQ wake, fixing MSI delivery makes EVERY op ~µs. CHEAP if
    it's the bug — check msix-tbl mask + q-vector bind for the blk queue at runtime.
 2. Multi-inflight: bounce POOL + per-descriptor completion tracking (used-ring id)
    + per-waiter wake, so many I/Os pipeline. Bigger rewrite.
Do (1) first (one instrumented boot) — likely the real root and a small fix.
