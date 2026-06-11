# state2 — console + drivers program: COMPLETE

Branch: main (all merged). Both parts of the program are done; the cleanup
pass is done. Nothing is mid-flight.

## What this program was
Bring the console/tty/driver stack to 100% Linux, no hacks/stubs/fakes, both
arches (x86_64 + aarch64) runtime-proven. Two parts:
- **Part B** = console-plan.md (the deep tty/VT/fbdev/console work).
- **Part C** = drivers.md (the driver-model + missing-drivers audit).

## Done (37 PRs, #1701–#1734 — see CHANGELOG "Console + Drivers program")
- Part A+B console-plan: #1701–#1718. One TtyStruct/NTty stack; real tty
  semantics (EINTR/VMIN-VTIME/IXON/hangup/pty-EOF); VT (DSR, glyphs, fonts>8,
  VT_PROCESS, resize, scrollback, /dev/vcs); /dev/console = vc_data + framebuffer
  keyboard login; real /dev/fb0 + mmap. Both arches log in (serial + framebuffer).
- Part C drivers.md: #1719–#1733. D1a model + /sys/bus; D2 stub removal; D3
  rng/ps2/nvme/ahci/vsock (real I/O); D4 UART split; D5 full DRM/KMS; D6 full
  fbdev; D7a /sys/block; D7b net statistics; D7c blk single-in-flight documented.
- Cleanup: #1734 make-test ReadOutcome fix (CI test gate green again).

## Verification gates (reusable)
- tools/boot-smoke-kbd-login.sh <arch>  — framebuffer keyboard login (QMP send-key)
- tools/boot-smoke-login.sh <arch>      — serial login + full app run
- tools/boot-smoke-probe.sh <arch> <probe> [t] — serial-login + run /bin/<probe> + assert PASS
- per-device probes in userspace/: hwrng/ptyhup/drm/drm2/drm3/fbdev2/sysblock/netstats/vsock/...

## Honest deferrals (correct as-is, each diagnosed — NOT façades)
- D1b probe-driven bring-up + linkme — boot-risky, no consumer (static device set).
- virtio-console (D3.2) — virtio_init_arch returns None for virtio-serial-pci
  (cap walk can't locate COMMON_CFG); written but NOT merged; needs focused work.
- drv remove/shutdown — dead code (no hotplug/unbind path); trait hooks exist.
- net RX-ring depth 1→N — depth-1 works; throughput-only.
- blk multiple-in-flight — single-in-flight is correct+real; no consumer + root
  risk → phase-17 block layer. Documented in drv-virtio-blk modern.rs.

## Known pre-existing issues (NOT from this program)
- **real DHCP gets no lease** — eth0's 10.0.2.15 is a STATIC rtnetlink seed
  (rtnetlink.rs:470), not DHCP; make smoke-dhcp-x86 times out (clean main fails
  identically). AF_PACKET TX + RX-to-socket delivery are sound; exact break needs
  an instrumented boot (single-RX-buffer/poll-cadence/iface-race suspects). A
  phase-8 net-client gap. See memory project_dhcp_static_seed + CHANGELOG.

## 5 latent bugs caught by the runtime-proof discipline
empty-DRM-card (#1727), ADDFB2 ioctl size 68→104 (#1728), AHCI FRE-before-BSY +
PxSIG-before-FRE (#1724), rng legacy-id needs disable-legacy=on (#1721),
fbdev↔pidfd inode collision 0x7001→0xFB00 (#1730).

## If continuing: next real work is phase-8 net (real DHCP) or virtio-console
(virtio-serial cap walk). Both out of the console+drivers scope just completed.
