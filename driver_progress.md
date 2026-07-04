# Driver progress

Date: 2026-07-04

`driver_plan.md` is the status ledger. This file records current evidence and
blockers for the active row.

Current marker: `>>> ACTIVE >>> B326-userspace-seat-driver-proof`.

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
| ARM MSI/ITS | Still needs a separate driver-plan item: generalize the ARM PCI MSI allocator to the GICv3 ITS path instead of relying on the current GICv2m-style MSI message path. |

## B326-userspace-seat-driver-proof

Status: `>>> ACTIVE >>> BLOCKED`.

Branch: `B326-userspace-seat-driver-proof`

Target row: QEMU/userspace proof for DRM/fbdev nodes, evdev nodes, ALSA nodes,
block/net discovery, uevent delivery, `/run/udev`, and seat state.

Evidence:

| Check | Result |
|---|---|
| Source audit | BLOCKED: current systemd install payload has PID1/systemctl/networkd only; no `udevadm`, `systemd-udevd`, `loginctl`, or `systemd-logind` staged for either arch. |
| `cargo check -p xtask` | PASS |
| `bash -n tools/boot-smoke-userspace-seat.sh` | PASS |
| `git diff --check` | PASS |
| `make smoke-userspace-seat-x86` | FAIL as expected: B002 device probes pass, `/run/udev`, udev data/tag index, seat0, udevadm/udevd, and loginctl/logind are missing. |
| `make smoke-userspace-seat-arm` | INTERRUPTED after live log showed systemd no-progress watchdog before the B326 oneshot could run. |

Runtime proof:

| Arch | Evidence |
|---|---|
| x86 | `fbdev_probe: PASS`; `drm_probe: PASS res=1280x800 crtcs=1 conns=1`; `sysblock_probe: PASS vda_size=2097152`; `snd_probe: PASS`; `rtlink_probe: PASS RTM_GETLINK dump 2 links, NLMSG_DONE ok`; `userspace_seat_smoke: FAIL missing /run/udev`; missing `/run/udev/data/c226:0`; missing `/run/udev/tags/master-of-seat/c226:0`; missing `/run/systemd/seats/seat0`; missing `/usr/bin/udevadm`; missing `/lib/systemd/systemd-udevd`; missing `/usr/bin/loginctl`; missing `/lib/systemd/systemd-logind`. |
| arm | Boot reached systemd PID1, then watchdog reported `no-progress: 0 context switches for 40s`; diagnostic service did not run. |

Next required work:

| Item | Required change |
|---|---|
| systemd payload | Build and stage real `udevadm`, `systemd-udevd`, `loginctl`, `systemd-logind`, libudev, udev rules, and required units for both arches. |
| B326 gate | Re-run `make smoke-userspace-seat-x86` and `make smoke-userspace-seat-arm`; only mark verified after both pass and report `/run/udev/tags/master-of-seat/c226:0` plus `CAN_GRAPHICAL=1`. |
