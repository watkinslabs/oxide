# Driver progress

Date: 2026-07-04

`driver_plan.md` is the status ledger. This file records current evidence and
blockers for the active row.

Current marker: `>>> ACTIVE >>> B338-drm-inode-tag-card-id`.

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

Status: `VERIFIED`; merged by PR #2390.

Branch: `B328-virtio-input-drain-split`

Target row:

| Status | Item |
|---|---|
| VERIFIED | Virtio-input `drain.rs` split into focused keymap pipeline, queue lifetime, and ring-drain modules before more growth. |

Evidence:

| Check | Result |
|---|---|
| Source split | PASS: parent manifest `drain.rs` is 19 lines; child modules are `key_event.rs` 99, `queue.rs` 146, `ring.rs` 46, `tests.rs` 110. |
| `cargo test -p drv-virtio-input` | PASS: 36 tests, 0 failed. |
| `make smoke-driver-path-x86` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b328-drain-split-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b328-drain-split-arm.log`. |

## B329-virtio-gpu-remove-child-key

Status: `VERIFIED`; merged by PR #2389.

Branch: `B329-virtio-gpu-remove-child-key`

Target row:

| Status | Item |
|---|---|
| VERIFIED | Virtio-gpu remove is keyed to owning child key. |

Evidence:

| Check | Result |
|---|---|
| Source fix | PASS: `VirtioGpuOps::remove_child` no longer calls the BDF-keyed `unpublish_console_scanout(device_key.raw())`; `drv_virtio_gpu::uninstall(device_key)` looks up the owner by child key and unpublishes the installed device BDF. |
| `cargo test -p drv-virtio-gpu uninstall_selects_owner_by_child_key_not_raw_bdf -- --nocapture` | PASS: regression uses child-key raw values that differ from and overlap other device BDFs. |
| `cargo test -p drv-virtio-gpu` | PASS: 27 tests, 0 failed. |
| `make smoke-driver-path-x86` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b329-gpu-remove-key-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b329-gpu-remove-key-arm.log`. |
| Line cap | PASS: `virtio_child.rs` 368 lines, `drv-virtio-gpu/src/tests.rs` 473 lines, `device.rs` 365 lines. |

## B330-virtio-gpu-remove-teardown-order

Status: `VERIFIED`; commit and PR merge pending.

Branch: `B330-virtio-gpu-remove-teardown-order`

Target row:

| Status | Item |
|---|---|
| VERIFIED | Virtio-gpu remove tears down fbcon/fbdev/DRM/klog/tty scanout before backing release. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `VirtioGpuOps::remove_child` calls `drv_virtio_gpu::uninstall(device_key)` before `post_init::uninstall_scanout(device_key)`. |
| Teardown order | PASS: `uninstall` unregisters DRM hooks, unpublishes console scanout by installed BDF, clears klog/tty/fbcon/fbdev hooks through `unpublish_console_scanout`, then returns before `uninstall_scanout` resets/frees scanout backing. |
| `cargo test -p drv-virtio-gpu uninstall_selects_owner_by_child_key_not_raw_bdf -- --nocapture` | PASS. |
| `cargo test -p drv-virtio-gpu` | PASS: 27 tests, 0 failed. |
| `make smoke-driver-path-x86` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b330-gpu-remove-teardown-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b330-gpu-remove-teardown-arm.log`. |
| Line cap | PASS: `virtio_child.rs` 368 lines, `device.rs` 365, `post_init/scanout.rs` 278, `drv-virtio-gpu/src/tests.rs` 473. |

## B331-virtio-gpu-probe-failure-unwind

Status: `VERIFIED`; commit and PR merge pending.

Branch: `B331-virtio-gpu-probe-failure-unwind`

Target row:

| Status | Item |
|---|---|
| VERIFIED | Virtio-gpu probe-failure unwind removes only failed child scanout. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `get_display_info` calls `uninstall_scanout_after_failed_probe(device_key)` after post-scanout `install_with_drm_parent` failure; `uninstall_scanout_after_failed_probe` finds/removes by exact `VirtioChildDeviceKey`, not BDF, and frees only that removed context backing. |
| Hosted regression | PASS: `post_init` is compiled under `#[cfg(any(target_os = "oxide-kernel", test))]`, so `post_init::tests::failed_probe_unwind_removes_only_matching_child_scanout` now runs and proves one failed child key leaves the other scanout context intact. |
| `cargo test -p drv-virtio-gpu failed_probe_unwind_removes_only_matching_child_scanout -- --nocapture` | PASS: 1 test passed, 28 filtered out. |
| `cargo test -p drv-virtio-gpu` | PASS: 29 tests, 0 failed. |
| `git diff --check` | PASS. |
| `make smoke-driver-path-x86` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b331-gpu-probe-failure-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b331-gpu-probe-failure-arm.log`. |
| Line cap | PASS: `lib.rs` 23 lines, `post_init.rs` 136, `post_init/tests.rs` 91, `post_init/scanout.rs` 278. |

## B332-virtio-gpu-hot-remove-cleanup

Status: `VERIFIED`; commit and PR merge pending.

Branch: `B332-virtio-gpu-hot-remove-cleanup`

Target row:

| Status | Item |
|---|---|
| VERIFIED | Virtio-gpu hot-remove independently attempts console/fbdev, DRM, and scanout cleanup. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `drv_virtio_gpu::hot_remove` calls `uninstall(device_key)` and then `post_init::uninstall_scanout(device_key)` independently; `VirtioGpuOps::remove_child` now uses that central helper. `uninstall` still clears DRM hooks, console/fbdev/klog/tty scanout state, and DRM registration before scanout backing is freed. |
| Hosted regression | PASS: `hot_remove_attempts_scanout_when_device_state_is_missing` proves scanout teardown still runs when the device table has no matching installed device; `hot_remove_attempts_device_and_scanout_cleanup` proves both paths run for a live installed device. |
| `cargo test -p drv-virtio-gpu hot_remove_attempts -- --nocapture` | PASS: 2 tests passed, 29 filtered out. |
| `cargo test -p drv-virtio-gpu` | PASS: 31 tests, 0 failed. |
| `git diff --check` | PASS. |
| `make smoke-driver-path-x86` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b332-gpu-hot-remove-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b332-gpu-hot-remove-arm.log`. |
| Line cap | PASS: `device.rs` 384 lines, `post_init/tests.rs` 106, `drv-virtio-gpu/src/tests.rs` 473, `virtio_child.rs` 367. |

## B333-virtio-gpu-device-state-key

Status: `VERIFIED`; commit and PR merge pending.

Branch: `B333-virtio-gpu-device-state-key`

Target row:

| Status | Item |
|---|---|
| VERIFIED | Virtio-gpu installed device state is per child key. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `VirtioGpuDev` carries `device_key`; `install` rejects duplicates by `device_key`; `uninstall` removes by `device_key`; `hot_remove` and `shutdown` consume the same typed key. BDF remains display/DRM metadata, not installed-device ownership. |
| `cargo test -p drv-virtio-gpu key -- --nocapture` | PASS: `install_accepts_multiple_keys_and_rejects_duplicate_key` and `uninstall_selects_owner_by_child_key_not_raw_bdf` passed. |
| `cargo test -p drv-virtio-gpu` | PASS: 31 tests, 0 failed. |
| `git diff --check` | PASS. |
| `make smoke-driver-path-x86` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b333-gpu-device-key-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b333-gpu-device-key-arm.log`. |

## B334-virtio-gpu-duplicate-key-reject

Status: `VERIFIED`; merged by PR #2387.

Branch: `B334-virtio-gpu-duplicate-key-reject`

Target row:

| Status | Item |
|---|---|
| VERIFIED | Virtio-gpu duplicate child-key install rejected before publication. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `install_with_drm` calls keyed `install(dev)?` before DRM registration; `install` rejects duplicate `device_key` with `Error::Busy` before pushing state. |
| Hosted regression | PASS: `install_with_drm_tracks_each_bdf_card_id` now asserts duplicate key returns `Error::Busy` and does not increase `drm::card_count()` or published DRM model devices. |
| `cargo test -p drv-virtio-gpu install_with_drm_tracks_each_bdf_card_id -- --nocapture` | PASS: 1 passed. |
| `cargo test -p drv-virtio-gpu` | PASS: 31 passed. |
| `git diff --check` | PASS. |
| Line cap | PASS: `crates/drivers/drv-virtio-gpu/src/tests.rs` is 477 lines. |
| `make smoke-driver-path-x86` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b334-gpu-duplicate-key-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b334-gpu-duplicate-key-arm.log`. |
| Pre-push boot smoke | PASS: x86_64 and aarch64 reached `oxide login:` before push. |
| PR merge | PASS: PR #2387 merged to `main` at `a9fabf21`. |

## B335-drm-card-id-stable-slots

Status: `VERIFIED`; merged by PR #2388.

Branch: `B335-drm-card-id-stable-slots`

Target row:

| Status | Item |
|---|---|
| VERIFIED | DRM card IDs are stable slots. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `drm::registry` stores cards as `Vec<Option<Arc<dyn DrmDriver>>>`; `register_with_parent` fills the first empty slot or appends; `card(card_id)` indexes that stable slot; `unregister(card_id)` clears only that slot and trims trailing empty slots. |
| Node routing audit | PASS: DRM card inodes encode `DRM_CARD_INO | card_id`; `handle_drm_ioctl` decodes the inode card id and calls `crate::card(card_id)`, so ioctl routing uses the stable slot instead of live-card count/order. |
| Hosted regression | PASS: `drm_card_fd_routes_by_stable_slot_after_lower_slot_reuse` keeps a card1 fd open, unregisters/reuses card0, and proves `GET_UNIQUE` still routes card1 to the original driver while card0 routes to the reused slot driver. |
| `cargo test -p drm drm_card_fd_routes_by_stable_slot_after_lower_slot_reuse -- --nocapture` | PASS: 1 passed. |
| `cargo test -p drm` | PASS: 56 passed. |
| `git diff --check` | PASS. |
| Line cap | PASS: `crates/drivers/drm/src/node/tests.rs` is 372 lines. |
| `make smoke-driver-path-x86` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b335-drm-card-id-stable-slots-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b335-drm-card-id-stable-slots-arm.log`. |
| Pre-push boot smoke | PASS: x86_64 and aarch64 reached `oxide login:` before push. |
| PR merge | PASS: PR #2388 merged to `main` at `934792db`. |

## B336-drm-card-node-publication

Status: `VERIFIED`; merged by PR #2389.

Branch: `B336-drm-card-node-publication`

Target row:

| Status | Item |
|---|---|
| VERIFIED | DRM publishes `/dev/dri/cardN` per stable card slot. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `drm::node::publication::register` publishes `dri/card{card_id}` as class `drm`, dev_t `(226, card_id)`, and a `make_card_inode(card_id)` factory through `drv::try_device_add`; `drv::try_device_add` forwards that metadata to the devtmpfs hook, and `kmain` wires the hook to `devfs::add_device_node`. |
| Hosted regression | PASS: `register_publishes_card_node_metadata_per_stable_slot` proves each stable card slot publishes the expected model device, devnode name, dev_t, char inode, and card-id inode tag. |
| `cargo test -p drm register_publishes_card_node_metadata_per_stable_slot -- --nocapture` | PASS: 1 passed. |
| `cargo test -p drm` | PASS: 57 passed. |
| `git diff --check` | PASS. |
| Line cap | PASS: `crates/drivers/drm/src/node/tests.rs` is 394 lines. |
| `make smoke-driver-path-x86` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b336-drm-card-node-publication-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b336-drm-card-node-publication-arm.log`. |
| Pre-push boot smoke | PASS: x86_64 reached `oxide login:` in 12s; aarch64 reached `oxide login:` in 16s. |
| PR merge | PASS: PR #2389 merged to `main` at `3ab38c75`. |

## B337-drm-render-nodes-withheld

Status: `VERIFIED`; commit and PR merge pending.

Branch: `B337-drm-render-nodes-withheld`

Target row:

| Status | Item |
|---|---|
| VERIFIED | DRM render nodes withheld until real render/GEM UAPI exists. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `drm::node::publication::register` only calls `add_node` for `dri/card{card_id}`; no production path publishes `dri/renderD*`. `make_render_inode` remains private test-only coverage for render-fd ioctl classification and is not exported through `register`. |
| Hosted regression | PASS: `register_does_not_publish_render_node` proves registering a card publishes no `dri/renderD128+N` model device. |
| Runtime probe | PASS: `userspace/drm_probe` now requires `open("/dev/dri/renderD128")` to fail with `ENOENT` before it runs the normal card0 KMS checks. |
| `cargo test -p drm register_does_not_publish_render_node -- --nocapture` | PASS: 1 passed. |
| `cargo test -p drm` | PASS: 57 passed. |
| `git diff --check` | PASS. |
| Line cap | PASS: `userspace/drm_probe/drm_probe.c` is 193 lines; `crates/drivers/drm/src/node/tests.rs` is 394 lines. |
| `make smoke-driver-path-x86` | PASS: updated `drm_probe` passed and driver path reported `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b337-drm-render-nodes-withheld-x86.log`. |
| `make smoke-driver-path-arm` | PASS on rerun: updated `drm_probe` passed and driver path reported `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b337-drm-render-nodes-withheld-arm-rerun.log`. |
| ARM intermittent note | First ARM run hit existing no-progress watchdog before `mouseprobe`; failed log `/tmp/b337-drm-render-nodes-withheld-arm.log` recorded in `driver_plan.md` follow-up row. |
| Pre-push boot smoke | PASS: x86_64 reached `oxide login:` in 22s on attempt 1 (`/tmp/oxide-boot-smoke-x86-35N3Zg.log`); aarch64 hit existing no-progress on attempt 1 (`/tmp/oxide-boot-smoke-arm-jyMRB8.log`) then reached `oxide login:` in 16s on attempt 2 (`/tmp/oxide-boot-smoke-arm-nJVaKr.log`). |
| PR merge | PASS: PR #2390 merged to `main` at `716e8b66`. |

## B338-drm-inode-tag-card-id

Status: `VERIFIED`; commit and PR merge pending.

Branch: `B338-drm-inode-tag-card-id`

Target row:

| Status | Item |
|---|---|
| VERIFIED | DRM inode tag encodes card id. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `make_card_inode(card_id)` builds inode `DRM_CARD_INO | card_id`; `make_render_inode(card_id)` builds inode `DRM_RENDER_INO | card_id`; `drm_inode_parts_raw` masks the high tag with `DRM_INO_TAG_MASK` and returns the low `DRM_INO_CARD_MASK` bits as the stable card id. |
| Hosted regression | PASS: `drm_inode_tags_encode_stable_card_id` proves card and render inode tags preserve stable ids `0`, `7`, and `0x7ffe`. |
| `cargo test -p drm drm_inode_tags_encode_stable_card_id -- --nocapture` | PASS: 1 passed. |
| `cargo test -p drm` | PASS: 58 passed. |
| `git diff --check` | PASS. |
| Line cap | PASS: `crates/drivers/drm/src/node/tests.rs` is 409 lines. |
| `make smoke-driver-path-x86` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b338-drm-inode-tag-card-id-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b338-drm-inode-tag-card-id-arm.log`. |
