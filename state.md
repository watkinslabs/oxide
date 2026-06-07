# Session hand-off — disk-based rootfs migration: BOTH ARCHES BOOT FROM DISK

## Status: migration core DONE + proven on x86 AND aarch64 (branch F405-disk-rootfs-migration)
Userspace is no longer baked into the kernel ELF — it's read from real virtio-blk
disks at runtime, the Linux way. x86 + arm both reach `oxide login:` mounting root
from the `oxide-root` disk. Stages:
- **Stage 0** (e239e7f4): overlay ImageDisk, vendored enablers built (libevent, Go
  toolchain, fzf/tmux/lazygit/yq — in vendor/, not yet staged).
- **Stage 1+3** (0e8323c6): real `drv-virtio-blk` BlockDevice driver (read/write/flush,
  multi-sector, GET_ID serial, vda/vdb naming, registry by_serial) + ext4
  de-singletonized (Ext4Mount{Arc<RootfsState>}, per-mount cache/orphans, high-32 inode
  marker, close-hook routes to owning mount). Adversarially reviewed; bugs fixed. 13+21
  hosted tests.
- **Stage 2** (45e318c1): xtask builds standalone root-<arch>.img (256/192 MiB) +
  home-<arch>.img; image_qemu + run-smokes attach both as virtio-blk serial=oxide-root/
  oxide-home on BOTH arches (arm had none — lockstep gap closed).
- **Stage 4** (f3cc88d2): kmain resequenced (PCI enum before mount); root mounts from
  oxide-root via by_serial + ext4::rootfs::init_from_dev; /home from oxide-home
  (graceful); embed include_bytes! + ImageDisk DELETED → small kernel, no boot hang.
  Both arches boot to login. x86 uses -m 1G (embed gone → 1G plenty).

## Open follow-ups (not blocking)
- **x86 PMM hang at -m 2G**: boot wedges before `pmm: ready` at 2G on x86 (arm fine at
  2G). Latent memmap/bitmap bug exposed when the migration briefly bumped x86 to 2G;
  reverted x86 to 1G. Fix for >1G x86 RAM (real distro needs it). Pre-existing, x86 was
  only ever booted at 1G before.
- **Stage 5 (optional)**: split heavy vendored tools onto a separate tools-<arch>.img
  mounted at /usr/local (user wanted a tools volume). Today root.img = base+tools, which
  boots fine; do this when the app backlog outgrows root.img.

## NEXT (resume the autonomous mission)
1. Push F405 through `make smoke` (boots both arches) → PR → merge to main (CI green via
   stub-blobs compile-check; kernel needs no rootfs blob now). Then update state.
2. **Resume vendoring the app backlog** onto root.img (now unbounded — disk, not kernel
   ELF): stage the already-built fzf/tmux/lazygit/yq + libevent; then delta, choose,
   yazi, neovim(C), mc(glib), btop/lnav(C++), man-db(gdbm), rsync, dialog. Pattern:
   fetch-<tool>.sh + vendor/<tool>/build.sh + gitignore allowlist + rootfs.rs put().
   Parallel sub-agents one tool each; orchestrator wires gitignore+rootfs; boot-test; commit.

## Resume command
```
cd /home/nd/oxide2 && git checkout F405-disk-rootfs-migration && git log --oneline -8
gh run list --limit 3
```
Branch counters: max F=405, B=62. alice/swordfish login. Commit author Chris Watkins.
Already-built-not-staged: libevent(lib), Go toolchain(vendor/go, gitignored),
fzf/tmux/lazygit/yq (vendor/, build.sh + binaries). 18 tools already staged in root.img.
