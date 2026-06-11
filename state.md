# state — session hand-off

Branch: main (clean, all merged @ eb737d8d). No work mid-flight.

## Headline
The **console-plan.md + drivers.md program is COMPLETE** — 35 PRs (#1701–#1735),
every functional change runtime-proven on BOTH x86_64 and aarch64 (real login /
real device I/O), no stubs/fakes. Full per-PR record in CHANGELOG.md → "Console +
Drivers program". Working scratch + deferral detail in state2.md.

## What landed
- **Part B — console/tty/fbdev/VT (#1701–#1718):** ONE TtyStruct/NTty stack
  (legacy tty::live retired); real tty semantics (EINTR, VMIN/VTIME, IXON,
  hangup, pty master-close→slave-EOF); VT (DSR/CPR, PSF2 glyphs + fonts>8,
  VT_PROCESS owner-checked, live resize, scrollback, /dev/vcs); /dev/console =
  real vc_data + **framebuffer keyboard login**; real /dev/fb0 + mmap.
- **Part C — drivers.md (#1719–#1734):** D1a driver model + /sys/bus; D2 stub
  removal; D3 missing drivers (virtio-rng, ps2-keyboard, nvme, ahci, virtio-vsock
  — real I/O); D4 UART crate split; D5 full DRM/KMS (info + dumb buffers +
  SETCRTC/flip, console-safe); D6 full fbdev (cmap/vsync/blank); D7a /sys/block;
  D7b net statistics; D7c blk single-in-flight documented.
- **Cleanup (#1734–#1735):** make-test ReadOutcome fix (CI test gate green);
  CHANGELOG + memory closeout.

## 5 latent bugs caught by the runtime-proof discipline
empty-DRM-card (#1727), ADDFB2 ioctl size 68→104 (#1728), AHCI FRE-before-BSY +
PxSIG-before-FRE (#1724), rng legacy-id needs disable-legacy=on (#1721),
fbdev↔pidfd inode collision 0x7001→0xFB00 (#1730).

## Honest deferrals (correct as-is, diagnosed — NOT façades)
- D1b probe-driven bring-up + linkme — boot-risky, no consumer (static devices).
- virtio-console (D3.2) — virtio_init_arch returns None for virtio-serial-pci
  (cap walk can't locate COMMON_CFG); written but NOT merged; needs focused work.
- drv remove/shutdown — dead code (no hotplug/unbind path); trait hooks exist.
- net RX-ring depth 1→N — depth-1 works; throughput-only.
- blk multiple-in-flight — single-in-flight is correct+real; no consumer + root
  risk → phase-17 block layer. Documented in drv-virtio-blk modern.rs.

## Known pre-existing issue (surfaced, not caused by this program)
- **real DHCP gets no lease** — eth0's 10.0.2.15 is a STATIC rtnetlink seed
  (rtnetlink.rs:470), not DHCP; `make smoke-dhcp-x86` times out (clean main fails
  identically). AF_PACKET TX + RX-to-socket delivery are sound; exact break needs
  an instrumented boot (single-RX-buffer / poll-cadence / iface-race suspects).
  Phase-8 net territory. See memory project_dhcp_static_seed.

## Verification gates (reusable)
- tools/boot-smoke-kbd-login.sh <arch>   — framebuffer keyboard login (QMP send-key)
- tools/boot-smoke-login.sh <arch>       — serial login + full app run
- tools/boot-smoke-probe.sh <arch> <probe> [t] — login + run /bin/<probe> + assert PASS

## First task next session
The console+drivers program is done; the next genuine items are OUT of that scope:
1. **Real DHCP (phase-8 net):** instrument a smoke-dhcp boot — confirm DHCPDISCOVER
   TX, then whether the OFFER is RX'd + delivered to udhcpc's AF_PACKET socket;
   likely the single RX buffer (drv-virtio-net rx0) drops the OFFER → deepen the
   RX ring; then drop the static 10.0.2.15 seed once real DHCP works.
2. **virtio-console:** focused virtio-serial cap-walk investigation (why
   virtio_init_arch returns None for device 0x1043).
Otherwise audit "what phase are we actually in" per 00§3 and pick the lowest
unfinished phase.




