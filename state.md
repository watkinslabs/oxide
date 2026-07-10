# Handoff — live-gnome sysinit blocker isolated to virtio-blk per-op I/O latency

Main = `ba551767`. 2 fixes merged this session; live-gnome blocker DIAGNOSED (not yet fixed).

## Landed (merged to main)
- **B699 (#2916)** ext4: op_lock held across `dev.flush` (sleeps on virtio) → boot
  livelock. Now defers the size-triggered batch commit out of op_lock (`create_op`,
  `creating` atomic). Boot cleared the old ~55s hard-hang; hwdb now finishes ~55s.
- **B700 (#2917)** net: race-free AF_UNIX accept park (`arm_accept_wait` under the
  accept_q lock, mirrors read_or_park) + 20ms safety-net rescan on accept (UNIX+TCP).

## THE remaining live-gnome blocker (goal 3) — full diagnosis in scratch/gnome-boot-campaign.md
`systemd-tmpfiles-setup-dev-early` stalls ~249s → boot never reaches getty/gdm.
Root cause chain (4 diagnostic boots + code trace, DEFINITIVE):
- Not AF_UNIX wake, not the scheduler tick, not data-journaling (data is already
  written direct-to-target = data=ordered). Writeback amplification is bounded
  (tests/writeback_amp_image passes ~8 ops/page).
- debug-taskdump: **systemd-hwdb blocks in ONE fsync ~50s** (nsysc frozen, low CPU
  → I/O-blocked). 13.5MB fresh file = ~27k single-block ops at **~2ms/op** (KVM
  should be µs). = [[hwdb-blocker-ext4-writeback-commits]].
- STRONGEST hypothesis: virtio-blk is **single-inflight** (`acquire_turn` serializes
  every op, engine.rs:205). Linux pipelines queue-depth 128+; ours pays the host
  round-trip SERIALLY → 27k×2ms≈50s. Secondary suspect: MSI not firing (enum logged
  virtio-blk `msi_fires=0`) so completions caught only by the 200k spin.

## First commands next session
1. `cd /home/nd/oxide/kernel && git log --oneline -3`  # main @ ba551767
2. Instrument `wait_for_completion` (drv-virtio-blk/src/modern/engine.rs:175):
   count park-vs-spin-hit + wall-ns/op behind a debug feature; ONE boot to confirm
   the ~2ms/op and whether it parks every op. (per user: no repeated long boots.)
3. Fix = multi-inflight virtio-blk queue OR coalesce contiguous writeback
   `write_byte_range` calls into multi-block requests (data blocks already direct).
   Validate hosted (StatsDev op-count, writeback_amp template) + e2fsck, then boot.

## Then continue the audit (scratch/kernel-audit2.md → gnome-boot-campaign.md ledger)
udev uevents, systemd mount contract, cgroup v2, AF_UNIX/dbus, procfs/sysfs, then
P1 (DRM/KMS, input, VT/logind, swap, net). Each ships a hosted harness; boot to verify.

## Gotchas
- NEVER `git add -A` (untracked ext42.md/ICE dumps). Stage explicit paths.
- ext4 work: iterate hosted + e2fsck, don't boot [[ext4-work-no-booting]].
- Boot only via qemu MCP (debug-dbus / debug-taskdump were the useful features here).
- ext4 = 100% complete/correct; this is a virtio-blk/perf issue, not an ext4 bug.
