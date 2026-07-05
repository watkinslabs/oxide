# Driver progress

Date: 2026-07-04

`driver_plan.md` is the status ledger. This file records current evidence and
blockers for the active row.

Current marker: `>>> ACTIVE >>> B328-virtio-input-drain-split`.

## B002-single-machine-desktop-proof

Status: `VERIFIED` and merged by PR #2378.

Branch: `B002-single-machine-desktop-proof`

Evidence:

| Check | Result |
|---|---|
| `cargo check -p drv-virtio-input` | PASS |
| `cargo check -p xtask` | PASS |
| `bash -n tools/boot-smoke-driver-path.sh` | PASS |
| `make smoke-driver-path-arm` | PASS |
| `make smoke-driver-path-x86` | PASS |

Runtime proof:

| Arch | Evidence |
|---|---|
| arm | `fbdev_probe: PASS`; `drm_probe: PASS res=1280x800 crtcs=1 conns=1`; `sysblock_probe: PASS vda_size=2097152`; `snd_probe: PASS`; `rtlink_probe: PASS RTM_GETLINK dump 2 links, NLMSG_DONE ok`; `b002_net_eth0: PASS`; `mouseprobe: ev0=4 ev1=7 motion=1 btn=1 syn=1`; `driver_path_smoke: PASS - GPU input sound block net`. |
| x86 | `fbdev_probe: PASS`; `drm_probe: PASS res=1280x800 crtcs=1 conns=1`; `sysblock_probe: PASS vda_size=2097152`; `snd_probe: PASS`; `rtlink_probe: PASS RTM_GETLINK dump 2 links, NLMSG_DONE ok`; `b002_net_eth0: PASS`; `mouseprobe: ev0=9 ev1=9 motion=1 btn=1 syn=1`; `driver_path_smoke: PASS - GPU input sound block net`. |

Notes:

| Item | Current finding |
|---|---|
| ARM virtio-input | QMP events reach the virtio-input used ring. ARM did not raise the device MSI during the smoke; evdev read/poll now calls the shared input drain before readiness checks so queued events publish to userspace. |
| ARM MSI/ITS | B326 now generalizes PCI MSI-X allocation on ARM to prefer GICv3 ITS/LPI and fall back to GICv2m only when no ITS doorbell is published. |

## B326-userspace-seat-driver-proof

Status: `VERIFIED` and merged by PR #2379.

Branch: `B326-userspace-seat-driver-proof`

Target row: userspace seat proof for DRM/fbdev nodes, evdev nodes, ALSA
nodes, block/net discovery, uevent delivery, `/run/udev`, and seat state.

Active loop: driver fixes use kernel-local fast smoke and targeted probes only,
on both `ARCH=x86_64` and `ARCH=aarch64`. Do not use GNOME/live image boots for
the 300+ driver-system work loop. GNOME/live image boot is a final seat proof
gate only after the driver path is clean on both arches.

Image-loop rule: `../oxide-images` `rootfs` is a cached base artifact per
profile/arch. Do not rebuild live GNOME rootfs for normal kernel-driver
iterations; rebuild only `kernel` + `boot-serial` unless packages or profile
configuration changed.

Evidence:

| Check | Result |
|---|---|
| Source audit | DONE for B326: per-item validation used fast driver smoke and targeted driver probes on both arches; GNOME remains final proof only. |
| `cargo check -p xtask` | PASS |
| `bash -n tools/boot-smoke-userspace-seat.sh` | PASS |
| `git diff --check` | PASS |
| kernel-local `make smoke-userspace-seat-x86` | DIAGNOSTIC ONLY: B002 device probes passed; old kernel-local rootfs lacked `/run/udev`, udev data/tag index, seat0, and loginctl/logind. |
| kernel-local `make smoke-userspace-seat-arm` | DIAGNOSTIC ONLY: interrupted after live log showed systemd no-progress watchdog before the B326 oneshot could run. |
| `cd ../oxide-images && make kernel boot-serial PROFILE=live-gnome ARCH=x86_64 KERNEL_DIR=../kernel` | PASS: exported kernel artifacts and wrote `output/live-gnome-x86_64-boot-serial.iso`. |
| `cd ../oxide-images && timeout 900s make run-serial-console PROFILE=live-gnome ARCH=x86_64 KERNEL_DIR=../kernel` | PARTIAL PASS: boot reached `graphical.target` and started `gdm.service`; seat-specific `/run/udev`/logind evidence still needs an in-image probe. Log: `../oxide-images/output/b326-live-gnome-x86_64.log`. |
| `cd ../oxide-images && make rootfs PROFILE=live-gnome ARCH=aarch64` | PASS one-time base seed: wrote `output/live-gnome-aarch64-root.img`. Slow path; do not repeat for kernel-only B326 iteration. Compose warning: `systemd-udev` trigger logged `Failed to write database /etc/udev/hwdb.bin: Function not implemented` but DNF completed. |
| `cd ../oxide-images && make kernel boot-serial PROFILE=live-gnome ARCH=aarch64 KERNEL_DIR=../kernel` | PASS: `xtask artifacts` now regenerates `target/artifacts/aarch64/kernel.Image` from the just-built ELF before image staging; wrote `output/live-gnome-aarch64-boot-serial.iso`. |
| `cd ../oxide-images && qemu-system-aarch64 ... output/live-gnome-aarch64-boot-serial.iso ...` | PARTIAL PASS: old ARM `[FAULT] esr=000000006234f841 ec=0x18` dynamic-linker halt is cleared. Boot completes modprobe units and starts `systemd-journald.service`, then stalls before `systemd-logind.service`/`gdm.service`. Latest log: `../oxide-images/output/b326-live-gnome-aarch64-fixed-image.log`. |
| kernel-local `make smoke-driver-path-x86` | PASS: GPU, input, sound, block, and net driver-path smoke completed. Log: `/tmp/b326-driver-path-x86-its.log`. |
| kernel-local `make smoke-driver-path-arm` | PASS: GPU, input, sound, block, and net driver-path smoke completed after ARM MSI-X switched to GICv3 ITS/LPI delivery. Log: `/tmp/b326-driver-path-arm-its.log`. |

Runtime proof:

| Arch | Evidence |
|---|---|
| x86 | Live GNOME image boot reached real Fedora userspace: `systemd-udevd-control.socket`, `systemd-udevd-kernel.socket`, `systemd-udev-trigger.service`, and `systemd-udevd.service` started; `systemd-logind.service` started; `gdm.service` started; `multi-user.target` and `graphical.target` reached. Remaining blockers: no explicit seat tag/CAN_GRAPHICAL probe yet; accounts-daemon, avahi-daemon, initctl, and systemd-update-utmp-runlevel failed. Kernel-local diagnostic also had B002 probes passing. |
| arm | Kernel-local fast driver path now passes with the real ARM PCI MSI-X path using GICv3 ITS/LPI. Earlier live GNOME image has a cached base root and fresh boot ISO; it reaches real Fedora systemd, queues `graphical.target`, opens udev sockets, finishes modprobe units, and starts `systemd-journald.service`. GNOME remains final proof only. |

Next required work:

| Item | Required change |
|---|---|
| Image path | DONE: `xtask artifacts --arch aarch64` rebuilds `kernel.Image` from the just-built `kernel.elf`; prior evidence showed `kernel.elf` had the sysreg fix while the raw Image was stale and still missing the branch. |
| B326 gate | Boot `live-gnome` through `../oxide-images` on x86_64 and aarch64; only mark verified after both report graphical seat readiness, including `/run/udev/tags/master-of-seat/c226:0` plus `CAN_GRAPHICAL=1`. |
| ARM MSI backend | DONE for fast driver path: virtio MSI-X allocation now prefers GICv3 ITS/LPI on ARM and falls back to GICv2m only when no ITS doorbell is published. |
| Evdev file semantics | DONE in hosted and fast boot proof: `cargo test -p drv-virtio-input` passes 30 tests covering model-owned event nodes, `/proc/bus/input/devices`, per-open `EVIOCGRAB`, `EBUSY` contention, non-owner read/poll exclusion, last-close grab release, `EVIOCSCLOCKID`, `EVIOCREVOKE`, and repeat ioctls. Fast driver smokes also pass on x86_64 (`/tmp/b326-evdev-x86.log`) and ARM (`/tmp/b326-evdev-arm.log`). |
| Evdev ioctl constants | DONE: evdev ioctl dispatch now uses named uapi constants for `_IOC` fields, request numbers, event ranges, clock id, and fixed struct sizes; regression keeps `EVIOCSFF` out of the `EVIOCGABS` range. Verified by `cargo test -p drv-virtio-input` plus x86_64/ARM driver-path smokes. |
| Virtio-input multi-device records | DONE: hosted tests prove multiple typed child-key records remain independent and `/proc/bus/input/devices` emits ordered `event0`/`event1` records. Fast x86_64 and ARM driver-path logs show `virtio-keyboard-pci` as `evdev_id=0 keyboard` and `virtio-mouse-pci` as `evdev_id=1 pointer`, with mouseprobe passing on both arches. |
| Obsolete EVIOC recognizer | DONE by source audit: `rg` finds evdev ioctl handling only in `drv_virtio_input::devfs::handle_evdev_ioctl(&File, ...)`, routed from `sys_ioctl` with the open file. There is no remaining crate-level EVIOC recognizer that bypasses file-aware grab/revoke semantics. |

## B327-virtio-input-queue-quiesce

Status: `VERIFIED`, commit/PR pending.

Branch: `B327-virtio-input-queue-quiesce`

Target rows:

| Status | Item |
|---|---|
| VERIFIED | Virtio-input clears event-queue bottom half when last queue removed. |
| VERIFIED | Virtio-input shutdown uses explicit event-queue quiesce path. |
| VERIFIED | Virtio-input hot-remove/shutdown address drain state by owning child key. |

Evidence:

| Check | Result |
|---|---|
| `cargo test -p drv-virtio-input drain::tests -- --nocapture` | PASS: targeted queue ownership tests prove removing one event queue keeps the shared drain handler, removing the last event queue clears it, and a missing child key does not remove another device queue. |
| `cargo test -p drv-virtio-input` | PASS: 36 hosted tests. |
| `make smoke-driver-path-x86` | DONE: PASS. Log: `/tmp/b327-queue-quiesce-x86.log`; runtime reported `driver_path_smoke: PASS - GPU input sound block net`. |
| `make smoke-driver-path-arm` | PASS on clean rerun. Log: `/tmp/b327-queue-quiesce-arm-rerun.log`; runtime reported `driver_path_smoke: PASS - GPU input sound block net`. Earlier failed log `/tmp/b327-queue-quiesce-arm.log` is retained as an intermittent ARM no-progress follow-up. |
| pre-push `boot-smoke` | PASS: x86 passed; ARM timed out on attempt 1 with the same no-progress watchdog, then reached `oxide login:` in 16s on attempt 2. Failed log: `/tmp/oxide-boot-smoke-arm-IdW5Zh.log`. |

Implementation note:

| Item | Current finding |
|---|---|
| Queue ownership | `shutdown_eventq` and `uninstall_eventq` now use typed `VirtioChildDeviceKey` ownership through `take_eventq`; shared softirq release is centralized in `release_handler_if_last`. |
| ARM intermittent finding | NOT DONE row recorded in `driver_plan.md`: ARM no-progress watchdog reproduced in fast driver-path and pre-push login smoke, but both gates passed on rerun; root-cause separately. |
| Follow-up ledger | NOT DONE follow-up recorded in `driver_plan.md`: split `drain.rs` into focused keymap pipeline, queue lifetime, and ring-drain modules before more growth. |

## B328-virtio-input-drain-split

Status: `CLAIMED`.

Branch: `B328-virtio-input-drain-split`

Target row:

| Status | Item |
|---|---|
| CLAIMED | Virtio-input `drain.rs` split into focused keymap pipeline, queue lifetime, and ring-drain modules before more growth. |

Evidence:

| Check | Result |
|---|---|
| Source claim | CLAIMED before code. |
