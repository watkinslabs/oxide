# Session hand-off — AUTONOMOUS RUN: disk-based rootfs migration

## Active mission (do not stop until done, then resume vendoring)
Replace the embedded-in-kernel rootfs (`include_bytes!` ROOTFS, ~200 MiB baked into
the kernel ELF → early-boot hang past ~128 MiB) with REAL DISKS read via virtio-blk +
ext4 at runtime — the Linux way. Kernel still loaded by GRUB (unchanged). Multiple
volumes: root (base distro + core tools), /home (user data), tools volume (heavy
vendored backlog) at /usr/local. Buddy MAX_ORDER is already 20 (=4 GiB) — NOT the
bottleneck; the embed itself is. Owner wants the rootfs disk image at 256 MiB
(rootfs.rs count=256 — keep it; that sizes the DISK image now, not the embed).

## Staged plan (from Plan agent audit — full detail in git log of this branch)
- **Stage 1** (foundation, hosted-test): new crate `crates/drivers/drv-virtio-blk`;
  promote the throwaway sector-1 probe in `crates/kernel/pci-boot/src/virtio_drv.rs`
  (blk branch ~:371-435, q0 setup :205-251, used-ring harvest :670-704) into a
  persistent `BlockDevice` (read T_IN + write T_OUT + flush; capacity/blk_size from
  virtio_blk_config). Register in `crates/kernel/block/src/registry.rs` by serial
  string. DO NOT touch kmain (Stage 4 owns boot wiring). Hosted-test the request
  encoding vs a fake ring.
- **Stage 3** (parallel w/ Stage 1, hosted-test): kill the ext4 singleton — make
  `Ext4RootfsFs` instance-carrying (`mount: Arc<ext4::Mount>` field), convert the ~40
  `MOUNT_PTR.load()` sites in `crates/kernel/ext4/src/rootfs.rs` to `self.mount`, add
  `Ext4RootfsFs::open(dev)->Arc<Self>`, fix the global orphan-set/inode-marker
  (0x6E54_0000) to be per-mount. Keep MOUNT_PTR as root during transition. Extend
  `set_test_mount` hosted test to 2 fixtures, assert no cross-contamination. DO NOT
  touch kmain.
- **Stage 2**: `tools/xtask/src/rootfs.rs` + `image_qemu.rs` + `tools/run-smokes.sh`:
  emit standalone `root-<arch>.img` (256 MiB) + `home-<arch>.img` + `tools-<arch>.img`
  (move the heavy vendored tools here → /usr/local). Attach all three as virtio-blk
  drives with serials `oxide-root`/`oxide-home`/`oxide-tools`. **ARM currently attaches
  NO -drive (rootfs baked in Image) — ADD the -drive/-device lines for ARM (lockstep
  risk #1).** Kernel IDs root by serial string (virtio_blk_config offset 24, 20 bytes).
- **Stage 4** (first boot-test, both arches): in `kmain.rs` move PCI enumeration
  (~:601) BEFORE `ext4::rootfs::init()` (~:497); look up root disk by serial →
  `Ext4RootfsFs::open(root_dev)` → register("/"). Drop the big embed (make ROOTFS a
  tiny stub / remove) so the kernel ELF shrinks → boots. Audit every
  `ext4::rootfs::read_file` caller in kmain (:533,:553,:621) — all must sit AFTER the
  new mount. Verify both arches reach `oxide login:`.
- **Stage 5**: kernel-mount /home + /usr/local from their disks (register after root).
- **Stage 6**: delete `const ROOTFS` + `ImageDisk` embed; keep `set_test_mount` fixture
  path for hosted tests.
- Then: **resume vendoring** the app backlog onto the tools volume (now unbounded):
  delta, choose, yazi, neovim, mc(glib), btop/lnav(C++), man-db(gdbm), rsync, dialog,
  + the lazygit/yq/fzf/tmux/libevent already built (vendor/, ready to stage).

## Risks (ranked): 1) ARM has no block device today — Stage 2 must add it + prove the
driver binds over ECAM on QEMU virt (PCI mem-enable bit). 2) virtio-blk write/used-ring
correctness. 3) ext4 singleton→instance 40-site churn. 4) Stage-4 boot reorder.

## Resume / first command each loop iteration
```
cd /home/nd/oxide2 && git checkout main && git pull
gh run list --limit 3   # main must stay green
# find current stage: did Stage 1 (drv-virtio-blk) land? Stage 3 (ext4 instance)? etc.
git log --oneline -15
```
Branch counters (derive from git log; max F=403, B=62). Commit+merge per stage, CI green.
alice/swordfish login for boot-tests. Already built+committed: 18 tools staged in the
(soon-removed) embed; libevent/Go-toolchain/fzf/tmux/lazygit/yq built in vendor/ (the
F404 wave) but NOT yet staged — they go on the tools volume in Stage 2/5.
