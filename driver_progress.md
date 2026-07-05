# Driver progress

Date: 2026-07-04

`driver_plan.md` is the status ledger. This file records current evidence and
blockers for the active row.

Current marker: `>>> ACTIVE >>> B344-drm-setcrtc-pageflip-card-route`.

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

Status: `VERIFIED`; merged by PR #2391.

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

Status: `VERIFIED`; merged by PR #2392.

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
| Pre-push boot smoke | PASS: x86_64 reached `oxide login:` in 22s on attempt 1 (`/tmp/oxide-boot-smoke-x86-7UiyH1.log`); aarch64 hit existing no-progress on attempt 1 (`/tmp/oxide-boot-smoke-arm-vsmd0t.log`) then reached `oxide login:` in 16s on attempt 2 (`/tmp/oxide-boot-smoke-arm-laxjZl.log`). |
| PR merge | PASS: PR #2391 merged to `main` at `81192089`. |

## B339-drm-card-ioctl-slot-routing

Status: `VERIFIED`; commit and PR merge pending.

Branch: `B339-drm-card-ioctl-slot-routing`

Target row:

| Status | Item |
|---|---|
| VERIFIED | DRM card ioctls route through matching backend slot. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `handle_drm_ioctl` decodes `card_id` from the fd inode via `drm_inode_parts(inode)` and calls `crate::card(card_id)`; `registry::card(card_id)` indexes the stable `Vec<Option<Arc<dyn DrmDriver>>>` slot, so ioctl routing is by encoded card id rather than live-card order. |
| Hosted regression | PASS: `drm_card_fd_routes_by_stable_slot_after_lower_slot_reuse` keeps a card1 fd open, unregisters/reuses lower slot card0, and proves card1 `GET_UNIQUE` still routes to its original backend while card0 routes to the reused backend. |
| `cargo test -p drm drm_card_fd_routes_by_stable_slot_after_lower_slot_reuse -- --nocapture` | PASS: 1 passed. |
| `cargo test -p drm` | PASS: 58 passed. |
| `git diff --check` | PASS. |
| Line cap | PASS: `crates/drivers/drm/src/node/tests.rs` is 409 lines. |
| `make smoke-driver-path-x86` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b339-drm-card-ioctl-slot-routing-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver-path-smoke: PASS - GPU input sound block net`; log `/tmp/b339-drm-card-ioctl-slot-routing-arm.log`. |
| PR merge | PASS: PR #2392 merged to `main` at `0a82d42a`. |

## B340-drm-sysfs-live-model-devices

Status: `VERIFIED` and merged by PR #2393.

Branch: `B340-drm-sysfs-live-model-devices`

Target row:

| Status | Item |
|---|---|
| VERIFIED | `/sys/class/drm` and `/sys/devices/virtual/drm` derive from live DRM model devices. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `drm_minors()` snapshots `drv::devices()` live, filters DRM class/dev_t/devname, derives the sysfs leaf and parent fields, and backs `/sys/class/drm`, `/sys/devices/virtual/drm`, and parented DRM directories for lookup and iteration. |
| Hosted regressions | PASS: `drm_class_enumerates_live_model_devices` and `drm_class_device_links_to_model_parent_when_present` cover model-backed class entries, virtual device entries, parented device links, and cleanup misses after model delete. |
| `cargo test -p sysfs drm_class -- --nocapture` | PASS: 2 passed. |
| `cargo test -p sysfs` | PASS: 25 passed. |
| `git diff --check` | PASS. |
| Line cap | PASS: `crates/kernel/sysfs/src/drm.rs` 443 lines; `crates/kernel/sysfs/src/bus/tests.rs` 420 lines. |
| `make smoke-driver-path-x86` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b340-drm-sysfs-live-model-devices-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b340-drm-sysfs-live-model-devices-arm.log`. |

## B341-virtio-gpu-drm-real-parent

Status: `VERIFIED` and merged by PR #2394.

Branch: `B341-virtio-gpu-drm-real-parent`

Target row:

| Status | Item |
|---|---|
| VERIFIED | Virtio-gpu registers DRM card devices with real virtio child parent. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `virtio-pci` publishes child model devices on bus `virtio`; `VirtioChildSession` stores `dev.addr`; `VirtioGpuOps` passes `Some(("virtio", session.device_addr()))`; DRM `register_with_parent` forwards to node publication and `add_node()` records `with_parent` on the DRM model device. |
| Hosted parent regression | PASS: `install_with_drm_records_model_parent` verifies the DRM card model device keeps the virtio parent tuple. |
| `cargo test -p drv-virtio-gpu install_with_drm_records_model_parent -- --nocapture` | PASS: 1 passed. |
| `cargo test -p drv-virtio-gpu` | PASS: 31 passed. |
| `cargo test -p virtio child_model_identity -- --nocapture` | PASS: 2 passed. |
| `cargo test -p virtio child_probe_lifecycle -- --nocapture` | PASS: 2 passed. |
| `cargo test -p pci-boot virtio -- --nocapture` | PASS: compile/test harness, 0 tests. |
| `git diff --check` | PASS. |
| Line cap | PASS: `drv-virtio-gpu/src/tests.rs` 477, `device.rs` 384, `pci-boot/src/virtio_child.rs` 367, `virtio_bus.rs` 144, `driver_progress.md` under cap. |
| `make smoke-driver-path-x86` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b341-virtio-gpu-drm-real-parent-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b341-virtio-gpu-drm-real-parent-arm.log`. |

## B342-parented-drm-minors-links

Status: `VERIFIED` and merged by PR #2395.

Branch: `B342-parented-drm-minors-links`

Target row:

| Status | Item |
|---|---|
| VERIFIED | Parented DRM minors live under owning device with class and `/sys/dev/char` links. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: DRM minors are synthesized from live `drv::devices()` records with parent bus/address, parent device dirs expose `drm` when parented minors exist, `/sys/class/drm/cardN` links to `../../devices/virtio/.../drm/cardN`, minor dirs expose `dev`/`device`/`subsystem`, and `/sys/dev/char/226:N` uses the DRM target helper for the parented path. |
| Hosted parented DRM/sysdev regressions | PASS: focused class, parent-dir, and `/sys/dev/char` tests prove the row. |
| `cargo test -p sysfs sys_dev_char_indexes_parented_drm_under_parent_device -- --nocapture` | PASS: 1 passed. |
| `cargo test -p sysfs drm_class_device_links_to_model_parent_when_present -- --nocapture` | PASS: 1 passed. |
| `cargo test -p sysfs drm_class_enumerates_live_model_devices -- --nocapture` | PASS: 1 passed. |
| Full `cargo test -p sysfs` | NOT USED as B342 pass: unrelated intermittent uevent isolation failed two different full-run tests, and a failing test passed alone; recorded in `driver_plan.md`. |
| `git diff --check` | PASS. |
| Line cap | PASS: `sysfs/src/drm.rs` 443, `bus/tests.rs` 420, `bus/index.rs` 95, `bus/device.rs` 309, `driver_progress.md` under cap. |
| `make smoke-driver-path-x86` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b342-parented-drm-minors-links-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b342-parented-drm-minors-links-arm.log`. |

## B343-scanout-backing-bdf-keyed

Status: `VERIFIED` and merged by PR #2396.

Branch: `B343-scanout-backing-bdf-keyed`

Target row:

| Status | Item |
|---|---|
| VERIFIED | Scanout backing state is BDF-keyed. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `ScanoutCtx` still keeps BDF only as PCI identity metadata, but console owner, fbdev ops, DRM scanout ops, runtime create/destroy/set/restore/flush, dimensions, framebuffer, readiness, publish, and unpublish now resolve by `VirtioChildDeviceKey` raw owner key. |
| Hosted key-vs-BDF regression | PASS: `failed_probe_unwind_removes_only_matching_child_scanout` now creates two scanout contexts with the same BDF and distinct child keys, proves dimensions resolve by key, and removes only the requested key. |
| `cargo test -p drv-virtio-gpu failed_probe_unwind_removes_only_matching_child_scanout -- --nocapture` | PASS: 1 passed. |
| `cargo test -p drv-virtio-gpu` | PASS: 31 passed. |
| `cargo test -p drm` | PASS: 58 passed. |
| `git diff --check` | PASS. |
| Line cap | PASS: `post_init.rs` 136, `scanout.rs` 288, `runtime.rs` 97, `post_init/tests.rs` 114, `device.rs` 384, `driver_progress.md` under cap. |
| `make smoke-driver-path-x86` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b343-scanout-backing-bdf-keyed-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b343-scanout-backing-bdf-keyed-arm.log`. |

## B344-drm-setcrtc-pageflip-card-route

Status: `VERIFIED, commit/PR merge pending`.

Branch: `B344-drm-setcrtc-pageflip-card-route`

Target row:

| Status | Item |
|---|---|
| VERIFIED | DRM SETCRTC/PAGE_FLIP hooks route by DRM card id to owning GPU. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: card inode tags decode to stable `card_id`; DRM ioctl dispatch passes that id to SETCRTC/PAGE_FLIP; handlers select `scanout_ops(card_id)` and virtio-gpu installs each card with owner `VirtioChildDeviceKey.raw()`. |
| `cargo test -p drm scanout_ops_route_by_card_id_to_driver_key -- --nocapture` | PASS: 1 passed. |
| `cargo test -p drm` | PASS: 59 passed. |
| `cargo test -p drv-virtio-gpu` | PASS: 31 passed. |
| `git diff --check` | PASS. |
| Line cap | PASS: `node/tests.rs` 472, `node/scanout.rs` 57, `crtc.rs` 433, `runtime.rs` 97, `driver_progress.md` under cap. |
| `make smoke-driver-path-x86` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b344-drm-setcrtc-pageflip-card-route-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b344-drm-setcrtc-pageflip-card-route-arm.log`. |
