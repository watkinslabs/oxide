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
