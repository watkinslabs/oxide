# Driver progress

Date: 2026-07-04

`driver_plan.md` is the status ledger. This file records current evidence and
blockers for the active row.

Current marker: `>>> ACTIVE >>> B002-single-machine-desktop-proof`.

## B002-single-machine-desktop-proof

Status: `>>> ACTIVE >>> VERIFIED` pending commit, PR, and merge.

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
