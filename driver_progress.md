# Driver progress

Date: 2026-07-05

`driver_plan.md` is the status ledger. This file records current evidence and
blockers for the active row.

Current marker: B450-device-del-registry-drop-after-teardown; IN AUDIT.

## B428-sysfs-explicit-bind-route

Status: `IN AUDIT`; claim commit pending.

Branch: `B428-sysfs-explicit-bind-route`

Target row:

| Status | Item |
|---|---|
| ACTIVE | Route explicit binds through sysfs driver `bind` control path. |

## B427-no-public-auto-bind

Status: `VERIFIED`; commit and PR merge pending.

Branch: `B427-no-public-auto-bind`

Target row:

| Status | Item |
|---|---|
| VERIFIED | Remove public `drv::auto_bind`; keep automatic attachment internal to `try_device_add` and `register_driver`. |

Evidence:

| Check | Result |
|---|---|
| Public API search | PASS: `rg auto_bind crates/drivers/drv/src crates/kernel crates/drivers --glob '*.rs'` finds no public or live `auto_bind` API. |
| Source audit | PASS: `try_device_add` calls private `attach_device_to_registered_drivers`; `register_driver` calls private `attach_driver_to_existing_devices`; both helpers call private `bind_inner`, so automatic attachment remains internal. |
| Focused hosted tests | PASS: `driver_registration_binds_existing_matching_devices`, `device_add_and_bind`, and `device_add_initial_probe_precedes_add_uevent_without_bind_change` each pass. |
| Full hosted regression | PASS: `cargo test -p drv -- --nocapture --test-threads=1` passed 24/24. |

## B426-drv-model-authoritative-proof

Status: `VERIFIED`; commit and PR merge pending.

Branch: `B426-drv-model-authoritative-proof`

Target row:

| Status | Item |
|---|---|
| VERIFIED | Make `drv::Device`, `drv::Driver`, `try_device_add`, `device_del`, `bind`, `bind_addr`, and `unbind` authoritative in `crates/drivers/drv/src/model.rs`. |

Evidence:

| Check | Result |
|---|---|
| Public API audit | PASS: `crates/drivers/drv/src/lib.rs` re-exports `Device`, `Driver`, `try_device_add`, `device_del`, `bind`, `bind_addr`, and `unbind` from `model`. |
| Model source audit | PASS: `model.rs` owns `DEVICES`, `MODEL_DRIVERS`, registration, automatic attachment, explicit bind/unbind, remove, devtmpfs/sysfs hooks, and shutdown traversal. |
| Production call sites | PASS: pci-boot, kmain platform devices, sysfs bus driver controls, devfs defaults, block, sound, DRM, fbdev, virtio-input, and virtio-rng route through `drv::register_driver`, `drv::try_device_add`, `drv::device_del`, `drv::bind_addr`, or `drv::unbind`. |
| Bypass search | PASS: no public `auto_bind`, `register_device`, or infallible `device_add` API remains in `crates/drivers/drv`, `crates/kernel`, or `crates/drivers`. |
| Hosted regression | PASS: `cargo test -p drv -- --nocapture --test-threads=1` passed 24/24. |

## B425-no-flat-driverentry-probeall

Status: `VERIFIED`; commit and PR merge pending.

Branch: `B425-no-flat-driverentry-probeall`

Target row:

| Status | Item |
|---|---|
| VERIFIED | Remove old flat `DriverEntry` / `probe_all(bdf)` live driver path. |

Evidence:

| Check | Result |
|---|---|
| Source search | PASS: `rg '\bDriverEntry\b|\bprobe_all\b|probe_all\(' crates userspace tools --glob '!target/**'` returns no live source hits. Remaining mentions are docs/history only. |
| Source audit | PASS: `crates/drivers/drv/src/model.rs` owns `Device`, `Driver`, `try_device_add`, `register_driver`, `bind_inner`, `attach_device_to_registered_drivers`, and `attach_driver_to_existing_devices`; binding resolves registered model drivers and calls `Driver::probe`. |
| Hosted regression | PASS: `cargo test -p drv -- --nocapture --test-threads=1` passed 24/24. |

## B424-bound-unbound-uevent-state-proof

Status: `VERIFIED`; commit and PR merge pending.

Branch: `B424-bound-unbound-uevent-state-proof`

Target rows:

| Status | Item |
|---|---|
| VERIFIED | Bound change uevents include `DRIVER=<name>`. |
| VERIFIED | Unbound change uevents do not carry stale driver ownership. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `/bin/uevent_probe` matches bind events on `ACTION=change`, `SUBSYSTEM=virtio`, `DEVPATH=/devices/virtio/<dev>`, and `DRIVER=virtio-snd`; it matches unbind events on the same action/subsystem/devpath while rejecting stale `DRIVER=virtio-snd`. |
| Hosted regression | PASS: `cargo test -p sysfs bind_unbind_emit_change_uevents_from_current_model_state -- --nocapture` passed on current source. |
| x86_64 live proof | PASS: `/tmp/b422-bind-unbind-uevent-stability-x86.log` contains `uevent_probe_unbind_change: PASS`, `uevent_probe_bind_change: PASS`, and final `uevent_probe: PASS netlink KOBJECT_UEVENT bind/unbind`. |
| aarch64 live proof | PASS: `/tmp/b422-bind-unbind-uevent-stability-arm.log` contains the same live proof lines. |

## B422-bind-unbind-uevent-stability

Status: `VERIFIED`; commit and PR merge pending.

Branch: `B422-bind-unbind-uevent-stability`

Target rows:

| Status | Item |
|---|---|
| VERIFIED | Bind/unbind change uevents must be stable under parallel tests and live udev monitor. |
| VERIFIED | Intermittent hosted sysfs uevent test isolation root cause. |

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: sysfs hosted tests now filter the shared `NETLINK_KOBJECT_UEVENT` stream for matching `ACTION`, `DEVPATH`, `SUBSYSTEM`, and driver-state entries; unregister-driver remove accounting uses a dedicated counter instead of the bind/unbind counter. |
| Live monitor proof | PASS: `/bin/uevent_probe` subscribes to the real kobject uevent netlink group, writes `/sys/bus/virtio/drivers/virtio-snd/unbind`, proves the matching unbind `change` event has no stale `DRIVER=virtio-snd`, writes `bind`, and proves the matching bind `change` event carries `DRIVER=virtio-snd`. |
| `cargo test -p sysfs bind_unbind_emit_change_uevents_from_current_model_state -- --nocapture` | PASS: 1 passed. |
| `cargo test -p sysfs -- --nocapture` | PASS: 25 passed, including the previously intermittent parallel uevent tests. |
| Musl userspace compile | PASS: `uevent_probe.c` compiles with repo x86_64 and aarch64 musl GCC using `-Wall -Wextra -Werror -static -no-pie`. |
| `git diff --check` | PASS. |
| Line cap | PASS: `uevent_probe.c` 176, `rootfs.rs` 370, `bus/tests.rs` 449, `char_class/tests.rs` 240. |
| `make smoke-driver-path-x86` | PASS: fast driver path plus live uevent proof; log `/tmp/b422-bind-unbind-uevent-stability-x86.log` contains `uevent_probe_unbind_change: PASS`, `uevent_probe_bind_change: PASS`, and `uevent_probe: PASS netlink KOBJECT_UEVENT bind/unbind`. |
| `make smoke-driver-path-arm` | PASS: fast driver path plus live uevent proof; log `/tmp/b422-bind-unbind-uevent-stability-arm.log` contains the same B422 live proof lines. |

## Archived Completed B327-B330

| Branch | Status | Evidence |
|---|---|---|
| B327-virtio-input-queue-quiesce | VERIFIED | Queue ownership tests, full virtio-input tests, x86/ARM driver-path proof; ARM intermittent logged in `driver_plan.md`. |
| B328-virtio-input-drain-split | VERIFIED | Drain split source audit, full virtio-input tests, x86/ARM driver-path proof. |
| B329-virtio-gpu-remove-child-key | VERIFIED | Child-key remove regression, full virtio-gpu tests, x86/ARM driver-path proof. |
| B330-virtio-gpu-remove-teardown-order | VERIFIED | Teardown-order source audit, full virtio-gpu tests, x86/ARM driver-path proof. |

## Archived Completed B331-B334

| Branch | Status | Evidence |
|---|---|---|
| B331-virtio-gpu-probe-failure-unwind | VERIFIED | Failed-probe unwind regression, full virtio-gpu tests, x86/ARM driver-path proof, PR #2392. |
| B332-virtio-gpu-hot-remove-cleanup | VERIFIED | Independent hot-remove cleanup regressions, full virtio-gpu tests, x86/ARM driver-path proof. |
| B333-virtio-gpu-device-state-key | VERIFIED | Per-child-key device-state regressions, full virtio-gpu tests, x86/ARM driver-path proof. |
| B334-virtio-gpu-duplicate-key-reject | VERIFIED | Duplicate-key publication regression, full virtio-gpu tests, x86/ARM driver-path, pre-push boot smoke, PR #2387. |

## Archived Completed B335-B336

| Branch | Status | Evidence |
|---|---|---|
| B335-drm-card-id-stable-slots | VERIFIED | Stable-slot routing regression, full DRM tests, x86/ARM driver-path proof, PR #2388. |
| B336-drm-card-node-publication | VERIFIED | Card-node publication regression, full DRM tests, x86/ARM driver-path proof, PR #2389. |
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

Status: `VERIFIED, PR #2397 merged`.

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
| Pre-push boot smoke | PASS: both arches reached `oxide login:` before push. |
| PR | PASS: PR #2397 merged and local `main` synced to `origin/main` at `55488c5b`. |

## B345-drm-dumb-fb-card-owned

Status: `VERIFIED, PR #2398 merged`.

Branch: `B345-drm-dumb-fb-card-owned`

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `DumbBuf` and `FbObj` carry `card_id`; ioctl, mmap, scanout, RMFB, and unregister paths look up/remove by `card_id`; inode mmap routing decodes the owning card id before table lookup. |
| `cargo test -p drm card_state_isolated -- --nocapture` | PASS: same numeric handle and same `fb_id` on two cards stay isolated across remove. |
| `cargo test -p drm` | PASS: 59 passed. |
| `git diff --check` | PASS. |
| Line cap | PASS: `dumb/tests.rs` 458, `dumb/tables.rs` 203, `dumb/ioctl.rs` 142, `driver_progress.md` under cap. |
| `make smoke-driver-path-x86` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b345-drm-dumb-fb-card-owned-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b345-drm-dumb-fb-card-owned-arm.log`. |
| Pre-push boot smoke | PASS: both arches reached `oxide login:` before push. |
| PR | PASS: PR #2398 merged and local `main` synced to `origin/main` at `16bd0bee`. |

## B346-drm-fb-scanout-resource-lifetime

Status: `VERIFIED`; merged by PR #2399.

Branch: `B346-drm-fb-scanout-resource-lifetime`

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `FbObj.scanout_res_id` owns the runtime resource id; SETCRTC/PAGE_FLIP reuse it through `fb_scanout_resource`; bind refuses missing, zero, or already-bound resources and destroys newly created resources on bind failure; RMFB detaches CRTC state then releases the scanout resource; unregister `clear_card_state` releases all card scanout resources. |
| `cargo test -p drm clear_card_state_releases_bound_scanout_resource -- --nocapture` | PASS: 1 passed. |
| `cargo test -p drm` | PASS: 60 passed. |
| `git diff --check` | PASS. |
| Line cap | PASS: `crates/drivers/drm/src/dumb/tests.rs` 495 lines, `dumb/tables.rs` 203, `dumb/ioctl.rs` 142, `driver_progress.md` below markdown cap. |
| `make smoke-driver-path-x86` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b346-drm-fb-scanout-resource-lifetime-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b346-drm-fb-scanout-resource-lifetime-arm.log`. |
| Pre-push boot smoke | PASS: x86_64 and aarch64 reached `oxide login:` before push. |
| PR | PASS: PR #2399 merged and local `main` synced to `origin/main` at `6ffbc9b7`. |

## B347-drm-unregister-drops-card-state

Status: `VERIFIED`; merged by PR #2400.

Branch: `B347-drm-unregister-drops-card-state`

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `registry::unregister(card_id)` removes the card slot, trims empty tail slots, then calls `crtc::clear_card_state(card_id)`, `dumb::clear_card_state(card_id)`, and `node::unregister(card_id)`. CRTC clear drops owner, current FB, and queued flip events for that card only. Dumb clear removes that card's FBs and buffers while leaving other cards' state intact. |
| Hosted regression | PASS: `unregister_drops_only_that_card_runtime_state` proves unregister clears owner/current-FB/events and FB table state for card0 without clearing card1. |
| `cargo test -p drm unregister_drops_only_that_card_runtime_state -- --nocapture` | PASS: 1 passed. |
| `cargo test -p drm` | PASS: 61 passed. |
| `git diff --check` | PASS. |
| Line cap | PASS: `crtc.rs` 438 lines, `tests.rs` 224, `dumb/tests.rs` 495. |
| `make smoke-driver-path-x86` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b347-drm-unregister-drops-card-state-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b347-drm-unregister-drops-card-state-arm.log`. |
| Pre-push boot smoke | PASS: x86_64 and aarch64 reached `oxide login:` before push. |
| PR | PASS: PR #2400 merged and local `main` synced to `origin/main` at `a62a9129`. |

## B348-drm-master-open-file-state

Status: `VERIFIED`; merged by PR #2401.

Branch: `B348-drm-master-open-file-state`

Evidence:

| Check | Result |
|---|---|
| Source audit | PASS: `file_token(file)` uses the `File` object address, so duplicate fds sharing the same `Arc<File>` share one open-file-description token. `set_master_owner`, `drop_master_owner`, `is_master`, KMS ioctls, and `DrmCardFileOps::on_release_file` all use that token. Separate opens get distinct tokens; last `File` drop releases master ownership. |
| Hosted regression | PASS: `drm_master_is_owned_by_open_file_description` now proves a cloned `Arc<File>` can re-SET_MASTER as the same owner, dropping only the clone keeps a separate open blocked with `EBUSY`, and dropping the last owner reference releases master so the separate open can acquire it. |
| `cargo test -p drm drm_master_is_owned_by_open_file_description -- --nocapture` | PASS: 1 passed. |
| `cargo test -p drm` | PASS: 61 passed. |
| `git diff --check` | PASS. |
| Line cap | PASS: `crates/drivers/drm/src/node/tests.rs` 474 lines. |
| `make smoke-driver-path-x86` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b348-drm-master-open-file-state-x86.log`. |
| `make smoke-driver-path-arm` | PASS: `driver_path_smoke: PASS - GPU input sound block net`. Log: `/tmp/b348-drm-master-open-file-state-arm.log`. |
| Pre-push boot smoke | PASS: x86_64 and aarch64 reached `oxide login:` before push. |
| PR merge + main sync | PASS: PR #2401 merged; local `main` equals `origin/main` at `bdb8d725`. |

## Archived Completed B349

| Branch | Status | Evidence |
|---|---|---|
| B349-drm-page-flip-file-events | VERIFIED | Per-card open-file page-flip poll/read regression, full DRM tests, x86/ARM driver-path, pre-push boot smoke, PR #2402, main sync `3287909f`. |

## Archived Completed B350

| Branch | Status | Evidence |
|---|---|---|
| B350-drm-magic-open-file-auth | VERIFIED | Live GET_MAGIC/AUTH_MAGIC allocation regressions, full DRM tests, x86/ARM driver-path, pre-push boot smoke, PR #2403, main sync `8e78fe0d`. |

## B351-drm-unique-version-uapi

Status: `VERIFIED`; merged by PR #2404.

Branch: `B351-drm-unique-version-uapi`

Evidence: source audit found `GET_UNIQUE` exposed bus id before `SET_VERSION` and copied partial undersized buffers; fixed per-open-file unique enable, release/unregister cleanup, Linux no-partial-copy behavior, and SET_VERSION driver/interface negotiation writeback. `drm_get_unique_copies_driver_bus_id_and_reports_full_length`, `drm_set_version_negotiates_supported_core_interface`, full `cargo test -p drm` with 63 tests, `git diff --check`, line cap, x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2404, and main sync `66d5c727` pass.

## B352-drm-atomic-empty-state

Status: `VERIFIED`; merged by PR #2405.

Branch: `B352-drm-atomic-empty-state`

Evidence: source audit found `struct drm_mode_atomic` missing `user_data` and ioctl size using 56 bytes instead of Linux 64 bytes; fixed ioctl `0xc04064bc`, full atomic flag mask, nonzero `reserved` rejection, PAGE_FLIP_EVENT/ASYNC rejection without support, and kept only internally gated empty state accepted. Focused atomic regression, full `cargo test -p drm` with 63 tests, `git diff --check`, line cap, x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2405, and main sync `be5399d3` pass.

## B353-drm-client-cap-rejects-unsupported

Status: `VERIFIED`; merged by PR #2406.

Branch: `B353-drm-client-cap-rejects-unsupported`

Evidence: source audit against Linux `drm_setclientcap` found unsupported caps must error before file-state mutation; fixed `SET_CLIENT_CAP` so stereo/atomic/aspect/writeback/cursor-hotspot reject value 0 and 1, leaving private cap state untouched. Focused unsupported-cap regression, full `cargo test -p drm` with 64 tests, `git diff --check`, line cap, x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2406, and main sync `f910022a` pass.

## B354-drm-get-cap-supported-only

Status: `VERIFIED`; merged by PR #2407.

Branch: `B354-drm-get-cap-supported-only`

Evidence: source audit found `GET_CAP` trusted `DrmDriver::cap` directly, allowing drivers to advertise unsupported PRIME/syncobj/async/page-flip-target/modifiers/cursor caps. Added DRM-core advertised-cap clamp and over-reporting-driver ioctl regression. Focused GET_CAP regression, full `cargo test -p drm` with 65 tests, `git diff --check`, line cap, x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2407, and main sync `7eadc40e` pass.

## B355-drm-raw-writes-rejected

Status: `VERIFIED`; merged by PR #2408.

Branch: `B355-drm-raw-writes-rejected`

Evidence: source audit found `DrmCardFileOps::write` and private `DrmSinkFileOps::write` both reject raw writes with `EINVAL`; no code change required. Existing `drm_nodes_do_not_acknowledge_raw_writes` covers card and render test inodes. Focused raw-write regression, full `cargo test -p drm` with 65 tests, `git diff --check`, line cap, x86_64/aarch64 driver-path smokes, PR #2408, and main sync `21e0a9ba` pass.

## B356-drm-addfb2-modifier-reject

Status: `VERIFIED`; merged by PR #2409.

Branch: `B356-drm-addfb2-modifier-reject`

Evidence: source audit found `addfb2` rejects any flags and separately rejects any nonzero `modifier[]` payload before handle lookup or FB allocation. Existing modifier-flag regression passed; added `addfb2_rejects_nonzero_modifier_even_without_modifier_flag` to prove modifiers cannot be silently ignored when flags are clear. Focused modifier regressions, full `cargo test -p drm` with 66 tests, `git diff --check`, line cap, x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2409, and main sync `8c2d61e3` pass. First ARM smoke attempt failed before kernel boot on external `vhost-vsock` guest-CID conflict; rerun passed.

## B357-drm-addfb-packed-rgb-validation

Status: `VERIFIED`; merged by PR #2410.

Branch: `B357-drm-addfb-packed-rgb-validation`

Evidence: source audit found `fb_plane_fits_buf` rejects zero dimensions, unsupported formats, short pitch, checked span overflow, and backing-buffer overflow for packed RGB. `addfb2` rejects nonzero flags, modifier payloads, missing handles, extra handles/pitches/offsets, and routes bounds through that helper; legacy `addfb` maps depth/bpp to packed RGB and uses the same bounds helper. Added `addfb2_rejects_unused_plane_offset_for_packed_rgb` and `legacy_addfb_rejects_framebuffer_larger_than_backing_buffer`; focused regressions, full `cargo test -p drm` with 68 tests, `git diff --check`, line cap, and fast x86_64/aarch64 driver-path smokes pass. First ARM smoke attempt failed before kernel boot on external `vhost-vsock` guest-CID conflict; no stale QEMU process was found and rerun passed.

## B358-fbdev-flush-blank-record

Status: `VERIFIED`; merged by PR #2411.

Branch: `B358-fbdev-flush-blank-record`

Evidence: source audit found `/dev/fbN` inodes carry `FbData { idx }` for read/write and `FB0_INO_BASE | idx` ioctl routing; `registry::ops_of`, `flush`, and `apply_blank` resolve `FbOps` by framebuffer idx, while virtio-gpu publishes ops with owner-key callbacks and stores the published fbdev idx in scanout context. Added `fbdev_ioctls_route_flush_blank_by_fb_inode_record` to prove FBIOBLANK and FBIO_WAITFORVSYNC entered through distinct `/dev/fbN` inodes call the selected record's ops key. Focused regression, full `cargo test -p fbdev` with 20 tests, `git diff --check`, line cap, and fast x86_64/aarch64 driver-path smokes pass. First ARM smoke attempt failed before kernel boot on external `vhost-vsock` guest-CID conflict; no stale QEMU process was found and rerun passed.

## B359-virtio-gpu-fbdev-index-owner

Status: `VERIFIED`; merged by PR #2412.

Branch: `B359-virtio-gpu-fbdev-index-owner`

Evidence: source audit found `publish_console_scanout` claims `CONSOLE_OWNER_KEY`, publishes fbdev ops with the virtio child owner key, records the returned fbdev idx in `ScanoutCtx`, and unwinds both idx and owner token on failure. `unpublish_console_scanout` only clears the matching owner token and unregisters the exact stored idx. Added `fbdev_idx_is_stored_and_taken_by_owner_key` and serialized post_init global-state tests to remove the hosted race. Focused regression, full `cargo test -p drv-virtio-gpu` with 32 tests, `git diff --check`, line cap, fast x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2412, and main sync `91039d81` pass.

## B360-console-fbdev-transactional-publish

Status: `VERIFIED`; merged by PR #2413.

Branch: `B360-console-fbdev-transactional-publish`

Evidence: source audit found `publish_console_scanout` claimed `CONSOLE_OWNER_KEY` before fbdev registration, ops install, and stored-index commit completed, creating a partial owner-visible publication window on failure paths. Split publication into `install_console_fbdev` and `commit_console_owner_key`; fbdev record, ops, and stored idx now complete before owner-token commit, and owner-commit failure clears the stored idx and unregisters the fbdev record. Added `console_owner_commits_after_fbdev_idx_is_stored` and `console_owner_commit_failure_unwinds_stored_fbdev_idx`; focused regressions, full `cargo test -p drv-virtio-gpu` with 34 tests, `git diff --check`, line cap, fast x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2413, and main sync `e0c60058` pass.

## B361-shutdown-scanout-quiesce-in-place

Status: `VERIFIED`; merged by PR #2414.

Branch: `B361-shutdown-scanout-quiesce-in-place`

Evidence: source audit found `shutdown_scanout` mutates the matching `ScanoutCtx` in place by setting `quiesced = true`, writes the device scanout disable register when live `cfg_va` exists, and does not remove CTX, fbdev idx, framebuffer VA/size, allocation count, command-buffer PA, or fbdev record. Added `shutdown_scanout_quiesces_without_dropping_publication_metadata`; focused regression, full `cargo test -p drv-virtio-gpu` with 35 tests, `git diff --check`, line cap, fast x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2414, and main sync `380a7e00` pass.

## B362-fbcon-foreground-owner

Status: `VERIFIED`; merged by PR #2415.

Branch: `B362-fbcon-foreground-owner`

Evidence: source audit found VT activation published fbcon renderer foreground and tty keyboard foreground only behind `target_os = "oxide-kernel"`, leaving hosted tests unable to prove the single foreground publication path. Added `publish_foreground`, called by `init` and completed switches, and made `tty::live` visible through the existing hosted feature for VT dev-tests only. Regression `activate_publishes_single_foreground_to_tty_and_fbcon` initializes fbcon and proves `ACTIVE_VT`, `tty::live::foreground()`, and `fbcon::kernel::foreground()` all move to VT3. `cargo check -p vt`, focused regression, full `cargo test -p vt` with 31 tests, `git diff --check`, line cap, fast x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2415, and main sync `1b3a3d14` pass.

## Recent Completed B363-B374

| Branch | Status | Evidence |
|---|---|---|
| B363-drm-dumb-mmap-pins-object | VERIFIED | DUMB mmap pins through VMA-owned backing with Drop/unpin; full DRM tests, arch driver-path proof, PR #2416, main sync `89ab2e44`. |
| B364-drm-map-dumb-cookie-validation | VERIFIED | MAP_DUMB cookie tag/layout rejection proof; full DRM tests, arch driver-path proof, PR #2417, main sync `a0cbb9bd`. |
| B365-fbdev-fbio-usercopy-bounds | VERIFIED | FBIO fixed/cmap usercopy ranges use checked exclusive-end validation; full fbdev tests, arch proof, PR #2418, main sync `70ac7dff`. |
| B366-fbdev-getcmap-transp-efault | VERIFIED | FBIOGETCMAP transparency pointer validates before writes; full fbdev tests, arch proof, PR #2419, main sync `50f507dc`. |
| B367-virtio-gpu-probe-unwind-proof | VERIFIED | Probe command/framebuffer allocations transfer or unwind by child key; full virtio-gpu tests, arch proof, PR #2420, main sync `c2e8e3cf`. |
| B368-virtio-net-netdev-publish-owner | VERIFIED | Netdev iface/runtime publication and removal are child-key owned; full virtio-net tests, arch proof, PR #2421, main sync `11a52b12`. |
| B369-virtio-net-rx-runtime-owner | VERIFIED | RX runtime install/removal and last-runtime shared teardown are child-key owned; full virtio-net tests, arch proof, PR #2422, main sync `92bf93aa`. |
| B370-virtio-net-no-boot-ipv4-policy | VERIFIED | RX runtime install seeds `0.0.0.0`, iface address hook updates later; full virtio-net tests, arch proof, PR #2423, main sync `c9a786f6`. |
| B371-virtio-net-install-remove-keyed | VERIFIED | Install/remove paths carry owning child key from PCI child dispatch into driver state; full virtio-net tests, arch proof, PR #2424, main sync `fb70eeb3`. |
| B372-virtio-net-keyed-cursors | VERIFIED | TX/RX cursors live in keyed device records; full virtio-net tests, arch proof, PR #2425, main sync `ebf774cb`. |
| B373-virtio-net-netdev-owning-key | VERIFIED | Published NetDev stores owning child key; full virtio-net tests, arch proof, PR #2426, main sync `b03912d3`. |
| B374-virtio-net-iface-rx-keyed-tables | VERIFIED | Registered iface and RX runtime tables are child-key owned; full virtio-net tests, arch proof, PR #2427, main sync `df4907d0`. |
| B375-virtio-net-ethn-visible-names | VERIFIED | Visible `ethN` names are child-runtime owned; full virtio-net tests, arch proof, PR #2428, main sync `66cf1bff`. |
| B376-virtio-net-rx-stats-per-netdev | VERIFIED | RX stats are child-runtime owned; full virtio-net tests, arch proof, PR #2429, main sync `b3643ee6`. |
| B377-virtio-net-ipv4-arp-runtime-owned | VERIFIED | IPv4 ARP cache is child-runtime owned; full virtio-net tests, arch proof, PR #2430, main sync `a81c39de`. |
| B378-virtio-net-hot-remove-key-cleanup | VERIFIED | Hot-remove clears keyed netdev/iface/RX runtime; full virtio-net tests, arch proof, PR #2431, main sync `3445c15a`. |
| B379-virtio-net-shared-rx-last-runtime | VERIFIED | Shared NetRx/ARP-GC lifetime is last-runtime owned; full virtio-net tests, arch proof, PR #2432, main sync `2178cd35`. |
| B380-virtio-net-ipv6-ndp-stack-owned | VERIFIED | IPv6 RX NDP learning is stack-owned; net NDP tests, virtio-net tests, arch proof, PR #2433, main sync `0fbf754b`. |
| B381-virtio-net-ipv6-tx-stack-ndp | VERIFIED | IPv6 TX NDP lookup is registered-stack owned; net/virtio-net tests, arch proof, PR #2434, main sync `cdd8d243`. |

## B379-B381 Recent Verified

Status: `VERIFIED`; merged by PRs #2432-#2434. Evidence is retained in the
recent-completed table above; main was synced after each merge through
`cdd8d243`.

## Recent Completed B382-B389

| Branch | Status | Evidence |
|---|---|---|
| B382-virtio-net-multidev-rebind-proof | VERIFIED | Fast `/init` multidev proof passes on x86_64/aarch64 for `eth0`/`eth1`, sysfs bind/unbind/rebind, restored virtio-net driver readdir state, and normal input tail; hosted checks, normal smoke, PR #2435 merge, and main sync `d09f5123` pass. Follow-up: stale direct driver symlink dcache after unbind. |
| B383-core-ipv6-ndp-iface-cache | VERIFIED | Core NDP map is `(iface, IPv6)` keyed and `unregister_iface` purges removed-iface entries; focused/NDP tests, line cap, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2436 merge, and main sync `505521d8` pass. First ARM driver-path run hit existing no-progress; rerun passed. |
| B384-virtio-vsock-remove-keyed | VERIFIED | Owner-keyed remove regression, full virtio-vsock tests, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2437 merge, and main sync `2efc98f8` pass. |
| B385-virtio-vsock-rx-bh-installed | VERIFIED | RX bottom-half ownership regression, full virtio-vsock tests, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2438 merge, and main sync `4db141ad` pass. |
| B386-net-vsock-owner-keyed-endpoints | VERIFIED | Owner-keyed endpoint TX routing regression, full vsock tests, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2439 merge, and main sync `947cb224` pass. |
| B387-af-vsock-bind-specific-local-cid | VERIFIED | Specific local-CID bind resolves live endpoint owner and rejects dead/quiesced CIDs; focused/full vsock tests, `syscalls` check, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2440 merge, and main sync `72aebeca` pass. |
| B388-vsock-listener-backlogs-owner-port | VERIFIED | Same-port listener backlogs are owner-keyed; focused/full vsock tests, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2441 merge, and main sync `a7a5312f` pass. |
| B389-vsock-close-releases-state | VERIFIED | Existing AF_VSOCK drop cleanup releases listener/backlog/connection state; cleanup/full vsock tests, x86_64/aarch64 driver-path proof, PR #2442 merge, and main sync `e3f505da` pass. |
| B390-virtio-rng-child-key-records | VERIFIED | Per-child-key virtio-rng records proven by source audit, hosted regression/full tests, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2443 merge, and main sync `68940f57`. |
| B391-B393 closeout | VERIFIED | B391/B392 virtio-rng and B393 virtio-snd keyed removal; hosted tests, arch proof, pre-push smoke, PRs #2444-#2446, main sync `6f09ae22`. |

## B412-B420 Current

| Branch | Status | Evidence |
|---|---|---|
| B412-probe-failure-devres-proof | VERIFIED | `VirtioProbeDevres` owns virtio-pci failed-probe cleanup/publish transfer; hosted fault-point lifecycle tests plus broad virtio child-driver tests and x86_64/aarch64 driver-path proof pass. |
| B413-devtmpfs-model-owned-publication | VERIFIED | Hardware-backed devtmpfs publication is model-owned across block, evdev, fbdev, DRM, hwrng, sound, console, and boot pseudo devices; remaining direct devfs users are non-hardware namespace entries. Hosted publication tests plus x86_64 `/tmp/b413-x86-driver-path.log` and aarch64 `/tmp/b413-arm-driver-path.log` pass. |
| B414-driver-devnode-readd-loops | VERIFIED | Added sound card unregister/register restore coverage; existing block, evdev, fbdev, DRM, and hwrng remove/readd loops pass. Hosted gate plus x86_64 `/tmp/b414-x86-driver-path.log` and aarch64 `/tmp/b414-arm-driver-path.log` pass; console tty nodes remain fixed boot-owned nodes covered by runtime. |
| B415-bind-unbind-readd-proof | NOT DONE | Audit found this is the aggregate QEMU hotplug/rebind acceptance row, not a hosted-only fix. Existing driver-core loops pass, but per-subsystem live-proof rows below must complete before B415 can become VERIFIED. |
| B416-nvme-ahci-multicontroller-proof | VERIFIED | Added opt-in two-NVMe/two-AHCI QEMU harness and `/bin/storage_multictrl_probe`; source audit confirms per-BDF state, hosted `cargo test -p drv -p sysfs -p block` passes, x86_64 `/tmp/b416-x86-storage-multictrl-3.log` and aarch64 `/tmp/b416-arm-storage-multictrl.log` prove sysfs unbind/rebind restores `/sys/block`. |
| B417-virtio-net-live-multidev-proof | VERIFIED | Existing `/bin/virtio_net_multidev_probe` and `OXIDE_VIRTIO_NET_MULTIDEV_SMOKE` QEMU mode prove two virtio-net devices, `eth0`/`eth1`, sysfs unbind/rebind, restored driver readdir state, and input tail. Hosted `cargo test -p drv-virtio-net -p net -p virtio -p pci-boot` plus x86_64 `/tmp/b417-x86-virtio-net-multidev.log` and aarch64 `/tmp/b417-arm-virtio-net-multidev.log` pass. |
| B418-virtio-gpu-live-multigpu-proof | VERIFIED | Added opt-in two-GPU QEMU mode and `/bin/virtio_gpu_multidev_probe`; source audit plus hosted `drv-virtio-gpu/drm/fbdev/virtio/pci-boot` tests pass. x86_64 `/tmp/b418-x86-virtio-gpu-multidev.log` and aarch64 `/tmp/b418-arm-virtio-gpu-multidev.log` prove two DRM cards, sysfs unbind/rebind, keyed `hot_remove`, and input/sound/block/net tail. |
| B419-virtio-vsock-live-multiendpoint-proof | VERIFIED | Fresh main `de65f27c`; fixed vsock proof to use direct `/init`, added visible probe phase logging, and made AF_VSOCK read/write waits poll the endpoint-owned RX hook before sleeping. Hosted `cargo test -p net -p drv-virtio-vsock -p pci-boot -- --nocapture --test-threads=1` passes. x86_64 `/tmp/b419-x86-vsock-multiendpoint-fastinit.log` and aarch64 `/tmp/b419-arm-vsock-multiendpoint-fastinit-3.log` both install cid=3/cid=4 and complete the host round-trip. |
| B420-virtio-snd-event-control-proof | VERIFIED | Fresh main `00aeb0da`; B399 already proved two live virtio-snd cards and rebind, but only by node presence plus `snd_probe` after rebind. Added Linux ALSA control ioctl proof for `controlC0`/`controlC1` before and after rebind: `SNDRV_CTL_IOCTL_CARD_INFO`, `PCM_NEXT_DEVICE`, `PCM_INFO` for playback/capture, empty `ELEM_LIST`, missing mixer element `ENOENT`, and `SUBSCRIBE_EVENTS`. Harness now surfaces `b420_` pass/fail lines. Direct musl builds pass for x86_64 and aarch64; `cargo test -p sound -p drv-virtio-snd -- --nocapture --test-threads=1` passes; fast live proofs pass in `/tmp/b420-x86-virtio-snd-event-control.log` and `/tmp/b420-arm-virtio-snd-event-control.log`. |

## B421 Current

| Branch | Status | Evidence |
|---|---|---|
| B421-pci-identity-mismatch-proof | VERIFIED | Fresh main `9e8594ad`; source audit found `try_device_add` rejects duplicate `(bus, addr)` and PCI publication only reuses an existing model device when vendor/device/class match. Added hosted regression `pci_identity_mismatch_does_not_replace_or_rebind` covering duplicate PCI addresses on bus 0 and bus 1 forms with different vendor/device/class; it proves the original model device remains bound, registry identity is not replaced, and the mismatched driver never probes. Focused regression and full serial `cargo test -p drv -- --nocapture --test-threads=1` pass. Fast x86_64 and aarch64 driver-path proofs pass in `/tmp/b421-pci-identity-mismatch-x86.log` and `/tmp/b421-pci-identity-mismatch-arm.log`; first ARM attempt hit the tracked systemd no-progress wedge and was recorded as `/tmp/b421-pci-identity-mismatch-arm-noprogress.log`. |

## B422 Current

| Branch | Status | Evidence |
|---|---|---|
| B422-bind-unbind-uevent-stability | IN AUDIT | Fresh main `c36158b7`; auditing sysfs bind/unbind change uevent delivery, hosted test isolation, and live udev-monitor proof requirements. |

## B428 Current

| Branch | Status | Evidence |
|---|---|---|
| B428-sysfs-explicit-bind-route | VERIFIED | Fresh main `bbe06158`; source audit proves `/sys/bus/<bus>/drivers/<driver>/bind` uses `drv::bind_addr(bus, addr, driver)` and `unbind` resolves the bound model device before `drv::unbind`. Driver directory symlinks are derived from current model binding state. Focused hosted regressions `cargo test -p sysfs driver_bind_unbind_attrs_drive_drv_model -- --nocapture` and `cargo test -p sysfs bind_unbind_emit_change_uevents_from_current_model_state -- --nocapture` pass. Runtime arch proof is inherited from B422 live x86_64/aarch64 bind/unbind uevent probe because this branch is docs/metadata only and does not change kernel or userspace code. |

## B429 Current

| Branch | Status | Evidence |
|---|---|---|
| B429-pci-model-bar-publication | VERIFIED | Fresh main `71a8020c`; source audit proves `pci-boot::enumerate_and_log` computes canonical PCI model addresses, calls `pci_resources_arch`, builds `drv::Device::new("pci", ...)`, attaches BAR resources with `with_resources`, and publishes through fallible `drv::try_device_add`; duplicate same-address matches are treated as existing only when vendor/device/class also match. Added `try_device_add_preserves_pci_bar_resources_and_rejects_republish` to prove BAR resources remain in the authoritative model record and duplicate publication does not replace them. Hosted checks pass: focused regression, full `cargo test -p drv -- --nocapture --test-threads=1` with 25 tests, full `cargo test -p pci -- --nocapture` with 10 tests, and `cargo test -p sysfs pci_device_exposes_indexed_bar_resource_attrs -- --nocapture`. Runtime lockstep passes: x86_64 `/tmp/b429-pci-model-bar-publication-x86.log` and aarch64 `/tmp/b429-pci-model-bar-publication-arm-2.log`; first ARM attempt failed before boot proof because vhost-vsock guest CID 3 was temporarily busy, no live QEMU remained, and rerun passed. |

## B430 Current

| Branch | Status | Evidence |
|---|---|---|
| B430-pci-model-driver-registration | VERIFIED | Fresh main `7936535e` after PR #2484 merge; source audit proves `pci-boot::register_pci_model_drivers` registers `drv_nvme::NVME_DRIVER`, `drv_ahci::AHCI_DRIVER`, and `virtio_drv::register_model_drivers` before enumerated PCI devices are published through `drv::try_device_add`; `virtio_drv` registers the `virtio-pci` `drv::Driver`, and source search found no NVMe/AHCI direct PCI-enumeration probe bypass. Added `uevent_probe_pci_drivers` to the fast driver-path userspace proof. Validation passes: x86_64 and aarch64 static-musl `uevent_probe.c` builds with `-Wall -Wextra -Werror -static -no-pie`, `cargo test -p pci-boot -- --nocapture` compile-check, full `cargo test -p drv -- --nocapture --test-threads=1` with 25 tests, `KEEP_LOG=/tmp/b430-pci-model-driver-registration-x86.log make smoke-driver-path-x86`, and `KEEP_LOG=/tmp/b430-pci-model-driver-registration-arm.log make smoke-driver-path-arm`. Both runtime logs contain `uevent_probe_pci_drivers: PASS nvme=1 ahci=1 virtio-pci=9` and `driver_path_smoke: PASS - GPU input sound block net`. |

## B431 Current

| Branch | Status | Evidence |
|---|---|---|
| B431-pci-driver-core-attach | VERIFIED | Fresh main `26eff5af` after PR #2486 merge; source audit proves `pci-boot::enumerate_and_log` calls `register_pci_model_drivers()` once before the device loop, then only publishes each enumerated PCI function through `publish_pci_model_device` and `drv::try_device_add`. Attachment is owned by `drv::try_device_add` -> `attach_device_to_registered_drivers` -> `bind_inner` -> `Driver::probe`. `rg` over `crates/kernel/pci-boot/src`, `drv-nvme`, and `drv-ahci` finds no enumeration-local `drv::bind`, `drv::bind_addr`, NVMe/AHCI init call, or direct virtio child probe bypass from enumeration. Hosted checks pass: `cargo test -p drv -- --nocapture --test-threads=1` and `cargo test -p pci-boot -- --nocapture`. Runtime proof is inherited from unchanged B430 code and passed x86_64/aarch64 logs `/tmp/b430-pci-model-driver-registration-x86.log` and `/tmp/b430-pci-model-driver-registration-arm.log`, each containing `uevent_probe_pci_drivers: PASS nvme=1 ahci=1 virtio-pci=9`. |

## B432 Current

| Branch | Status | Evidence |
|---|---|---|
| B432-pci-publication-idempotent-proof | VERIFIED | Fresh main `20a8dce9` after PR #2487 merge; source audit proves `publish_pci_model_device` constructs `drv::Device::new("pci", ...)` with BAR resources and publishes only through fallible `drv::try_device_add`. On `drv::Error::Busy`, it returns an existing model record only when bus, addr, vendor, device, and class all match; other errors return `None`, so publication is fallible rather than forced. Hosted regressions pass: `cargo test -p drv try_device_add_preserves_pci_bar_resources_and_rejects_republish -- --nocapture`, `cargo test -p drv pci_identity_mismatch_does_not_replace_or_rebind -- --nocapture`, and `cargo test -p pci-boot -- --nocapture`. Runtime proof is inherited from unchanged B429/B430 code and passed x86_64/aarch64 fast driver-path logs with PCI driver bindings. |

## B433 Current

| Branch | Status | Evidence |
|---|---|---|
| B433-model-binding-rejects-bound-devices | VERIFIED | Fresh main `114fdf3d` after PR #2488 merge; source audit proves `bind_inner` checks `dev.bound()` first and returns `drv::Error::AlreadyBound` before `find_driver_on_bus`, bus/match validation, `Driver::probe`, state update, or bind hook. Automatic attach paths skip already-bound devices before calling `bind_inner`, and sysfs maps `AlreadyBound` to `VfsError::Ebusy`. Hosted proof passes: `cargo test -p drv device_add_and_bind -- --nocapture`, `cargo test -p drv repeated_bind_unbind_keeps_model_state_consistent -- --nocapture`, `cargo test -p sysfs driver_bind_unbind_attrs_drive_drv_model -- --nocapture`, and full `cargo test -p drv -- --nocapture --test-threads=1` with 25/25 tests. This branch changes only docs/metadata; x86_64/aarch64 runtime proof is inherited from unchanged merged fast driver-path smokes for B430/B432-era driver-core code. |

## B434 Current

| Branch | Status | Evidence |
|---|---|---|
| B434-model-binding-bus-driver-match | VERIFIED | Fresh main `b8ccf81a` after PR #2489 merge; source audit proves `match_driver` only considers drivers on `dev.bus`, `find_driver_on_bus` resolves explicit binds by `(bus, driver_name)`, and `driver_matches_device` rejects wrong-bus drivers before checking `driver_override` or `Driver::matches`. `bind_inner` then returns `drv::Error::NoMatch` when a same-bus driver exists but does not match the device. Added regression `bind_rejects_same_bus_driver_when_device_does_not_match`, including cleanup with `device_del` after an initial full-suite run exposed test registry leakage. Hosted proof passes: the new focused test, `cargo test -p drv bind_resolves_driver_on_device_bus -- --nocapture`, `cargo test -p drv driver_override_stays_on_device_bus -- --nocapture`, `cargo test -p drv driver_names_are_bus_scoped -- --nocapture`, and full `cargo test -p drv -- --nocapture --test-threads=1` with 26/26 tests. Pre-push boot smoke passed on x86_64 and aarch64; ARM reached `oxide login:` in 26s on attempt 1. |

## B435 Current

| Branch | Status | Evidence |
|---|---|---|
| B435-model-binding-calls-probe | VERIFIED | Fresh main `8f884b46` after PR #2490 merge; source audit proves `bind_inner` calls `driver.probe(dev)?` after already-bound, bus lookup, and match validation, and before setting `dev.driver` or emitting the bind hook. Hosted probe-counter coverage passes: `cargo test -p drv driver_registration_binds_existing_matching_devices -- --nocapture`, `cargo test -p drv failed_probe_leaves_device_unbound_and_retriable -- --nocapture`, `cargo test -p drv repeated_bind_unbind_keeps_model_state_consistent -- --nocapture`, `cargo test -p drv device_add_initial_probe_precedes_add_uevent_without_bind_change -- --nocapture`, and full `cargo test -p drv -- --nocapture --test-threads=1` with 26/26 tests. Branch is docs/metadata only; x86_64/aarch64 runtime proof is inherited from unchanged B434 pre-push boot-smoke PASS. |

## B436 Current

| Branch | Status | Evidence |
|---|---|---|
| B436-model-binding-records-after-probe | VERIFIED | Fresh main `076f568e` after PR #2491 merge; source audit proves `bind_inner` executes `driver.probe(dev)?` before assigning `*dev.driver.lock() = Some(driver_name)`, so failed probes return before recording a binding or firing a bind hook. Hosted checks pass: `cargo test -p drv failed_probe_leaves_device_unbound_and_retriable -- --nocapture`, `cargo test -p drv driver_registration_binds_existing_matching_devices -- --nocapture`, `cargo test -p drv device_add_initial_probe_precedes_add_uevent_without_bind_change -- --nocapture`, and full `cargo test -p drv -- --nocapture --test-threads=1` with 26/26 tests. Branch is docs/metadata only; x86_64/aarch64 runtime proof is inherited from unchanged B434 pre-push boot-smoke PASS. |

## B437 Current

| Branch | Status | Evidence |
|---|---|---|
| B437-probe-failure-unbound-retriable | VERIFIED | Fresh main `e92b7401` after PR #2492 merge; source audit proves `bind_inner` propagates `Driver::probe` failure through `driver.probe(dev)?` before assigning `dev.driver`. Hosted regression `failed_probe_leaves_device_unbound_and_retriable` proves automatic probe failure leaves `dev.bound() == None`, then two explicit `bind` retries each return `drv::Error::ProbeFailed`, increment the failing probe counter, and still leave the device unbound. Checks pass: `cargo test -p drv failed_probe_leaves_device_unbound_and_retriable -- --nocapture` and full `cargo test -p drv -- --nocapture --test-threads=1` with 26/26 tests. Branch is docs/metadata only; x86_64/aarch64 runtime proof is inherited from unchanged B434 pre-push boot-smoke PASS. |

## B438 Current

| Branch | Status | Evidence |
|---|---|---|
| B438-driver-registration-attaches-existing | VERIFIED | Fresh main `424d9245` after PR #2493 merge; source audit proves `register_driver` inserts the new driver, publishes the driver hook, then calls `attach_driver_to_existing_devices`, which scans current devices, skips already-bound or non-matching entries, and calls `bind_inner` for existing unbound matches. Hosted checks pass: `cargo test -p drv driver_registration_binds_existing_matching_devices -- --nocapture`, `cargo test -p drv duplicate_driver_registration_does_not_reprobe_existing_devices -- --nocapture`, and full `cargo test -p drv -- --nocapture --test-threads=1` with 26/26 tests. Branch is docs/metadata only; x86_64/aarch64 runtime proof is inherited from unchanged B434 pre-push boot-smoke PASS. |

## B439 Current

| Branch | Status | Evidence |
|---|---|---|
| B439-driver-unregistration-detaches-bound | VERIFIED | Fresh main `583c456b` after PR #2494 merge; source audit proves `unregister_driver` first confirms the driver exists, walks current devices, calls `unbind` for devices bound to that bus/name, and only then removes the driver from `MODEL_DRIVERS`. Hosted checks pass: `cargo test -p drv unregister_driver_unbinds_devices_before_removing_driver -- --nocapture` and full `cargo test -p drv -- --nocapture --test-threads=1` with 26/26 tests. The regression proves remove is called, `dev.bound()` becomes `None`, the driver disappears from `driver_names_for_bus`, later bind fails with `NotFound`, and a second unregister fails with `NotFound`. Branch is docs/metadata only; x86_64/aarch64 runtime proof is inherited from unchanged B434 pre-push boot-smoke PASS. |

## B440 Current

| Branch | Status | Evidence |
|---|---|---|
| B440-new-device-attach-after-publication | VERIFIED | Fresh main `83af070e` after PR #2495 merge; source audit proves `try_device_add` rejects duplicate identity before publication, pushes the device into the registry, fires the devtmpfs hook for owned `/dev` nodes, calls `attach_device_to_registered_drivers(&d, false)` for initial auto-probe with bind-change events suppressed, then fires the sysfs add hook. Hosted checks pass: `cargo test -p drv device_add_initial_probe_precedes_add_uevent_without_bind_change -- --nocapture`, `cargo test -p sysfs device_add_uevent_includes_initial_bound_driver_state -- --nocapture`, and full `cargo test -p drv -- --nocapture --test-threads=1` with 26/26 tests. The driver-model test proves observed order `devtmpfs`, `probe`, `sysfs-add` and zero bind-change events; the sysfs test proves the add uevent includes current `DRIVER=` state. Branch is docs/metadata only; x86_64/aarch64 runtime proof is inherited from unchanged B434 pre-push boot-smoke PASS. |

## B441 Current

| Branch | Status | Evidence |
|---|---|---|
| B441-initial-autoprobe-no-bind-change | VERIFIED | Fresh main `32df2ea1` after PR #2496 merge; source audit proves `try_device_add` calls `attach_device_to_registered_drivers(&d, false)`, and `bind_inner` only fires `BIND_HOOK` when `emit_bind_event` is true. Hosted checks pass: `cargo test -p drv device_add_initial_probe_precedes_add_uevent_without_bind_change -- --nocapture` and full `cargo test -p drv -- --nocapture --test-threads=1` with 26/26 tests. The focused regression installs a bind hook, auto-probes a matching registered driver, verifies the device is bound, verifies sysfs add sees the bound state, and verifies `ADD_BIND_EVENTS == 0`. Branch is docs/metadata only; x86_64/aarch64 runtime proof is inherited from unchanged B434 pre-push boot-smoke PASS. |

## B442 Current

| Branch | Status | Evidence |
|---|---|---|
| B442-add-uevent-driver-state | VERIFIED | Fresh main `d5186887` after PR #2497 merge; source audit proves `crates/kernel/sysfs/src/bus/device.rs::dev_uevent_env` builds uevent environment from model state and appends `DRIVER=<name>` only when `dev.bound()` returns a driver, while `publish_device_cb`, `remove_device_cb`, and `bind_device_cb` emit that current environment. Hosted checks pass: `cargo test -p sysfs device_add_uevent_includes_initial_bound_driver_state -- --nocapture` and `cargo test -p sysfs bind_unbind_emit_change_uevents_from_current_model_state -- --nocapture`. The first regression proves initial add uevents include `ACTION=add`, platform `DEVPATH`, `SUBSYSTEM`, and current `DRIVER=` after auto-probe; the second proves bound change uevents carry `DRIVER=` and unbound change uevents omit stale driver ownership. Branch is docs/metadata only; x86_64/aarch64 runtime proof is inherited from unchanged B434 pre-push boot-smoke PASS. |

## B443 Current

| Branch | Status | Evidence |
|---|---|---|
| B443-platform-serial-model-attach | VERIFIED | Fresh main `a6fc640d` after PR #2500 merge; source audit proves `crates/kernel/kmain/src/kmain/runtime.rs::init_serial_console` gets the active `drv_serial::uart_driver()`, publishes `platform/serial0` via `platform_device_or_panic` / `drv::try_device_add`, registers the UART model driver with `drv::register_driver`, and installs the serial byte sink only when `dev.bound()` equals that driver's model name. The x86_64 UART driver is `8250-serial` and the aarch64 UART driver is `pl011-serial`; both implement `drv::Driver` on bus `platform`, match only addr `serial0`, and do hardware detection/IRQ setup in `probe`. Hosted checks pass: `cargo test -p drv-uart-16550 -p drv-uart-pl011 -p drv-serial -- --nocapture --test-threads=1`, `cargo test -p drv -- driver_registration_binds_existing_matching_devices -- --nocapture`, and `cargo test -p drv -- try_device_add_rejects_duplicate_bus_identity -- --nocapture`. Runtime checks pass: `make smoke-x86 SMOKE_TIMEOUT=240` reached `oxide login:` in 32s attempt 1, and `make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 38s attempt 1. |

## B444 Current

| Branch | Status | Evidence |
|---|---|---|
| B444-i8042-platform-model-attach | VERIFIED | Fresh main `6fe6f3f6` after PR #2501 merge; source audit proves x86_64 `crates/kernel/kmain/src/kmain/runtime.rs::init_ps2_keyboard` gets `drv_ps2_keyboard::driver()`, installs probe data with `configure_probe`, publishes `platform/i8042` through `platform_device_or_panic` / `drv::try_device_add`, then calls `drv::register_driver(ps2_drv)`. `crates/drivers/drv-ps2-keyboard/src/lib.rs` implements `Ps2KbdDriver` as a `platform` model driver named `i8042-kbd` that matches only addr `i8042`; `probe` performs i8042 bring-up and IRQ1 setup, returning `ProbeFailed` on absent hardware so the model device remains unbound. The aarch64 boot hook is an explicit no-op and the driver crate uses the no-op shell outside `x86_64` `oxide-kernel`, which is correct because QEMU `virt` has no i8042. Hosted checks pass: `cargo test -p drv-ps2-keyboard -- --nocapture`, `cargo test -p drv -- driver_registration_binds_existing_matching_devices -- --nocapture`, and `cargo test -p drv -- try_device_add_rejects_duplicate_bus_identity -- --nocapture`. Runtime x86_64 proof passes: `SMOKE_KEEP_LOG=/tmp/b444-i8042-platform-model-attach-x86.log ./tools/boot-smoke.sh x86 240` reached `oxide login:` in 12s attempt 1, and the saved log contains `[INFO]  i8042 keyboard detected`. aarch64 runtime non-regression is inherited from B443 `make smoke-arm SMOKE_TIMEOUT=300` because B444 is docs/metadata only and the i8042 path is compiled out on aarch64. |

## B445 Current

| Branch | Status | Evidence |
|---|---|---|
| B445-sysfs-bind-entry-production | VERIFIED | Fresh main `7e807a39` after PR #2502 merge; source audit proves `crates/kernel/sysfs/src/bus/hooks.rs` registers `/sys/bus/{pci,virtio,platform}/drivers`, `crates/kernel/sysfs/src/bus/driver.rs` exposes `bind` and `unbind` under each driver dir, bind writes parse the device token and call `drv::bind_addr(bus, addr, driver)`, unbind resolves the currently bound model device before `drv::unbind`, and driver symlinks are derived from current model binding state. Focused hosted regressions pass: `cargo test -p sysfs driver_bind_unbind_attrs_drive_drv_model -- --nocapture`, `cargo test -p sysfs driver_bind_attr_preserves_unbound_state_on_probe_failure -- --nocapture`, and `cargo test -p sysfs bind_unbind_emit_change_uevents_from_current_model_state -- --nocapture`. Runtime arch proof is inherited from already-merged x86_64/aarch64 bind/unbind uevent and driver-path smokes because B445 changes only docs/metadata and the production sysfs code is unchanged on this branch. |

## B446 Current

| Branch | Status | Evidence |
|---|---|---|
| B446-model-unbind-remove-before-clear | VERIFIED | Fresh main `c51f20f7` after PR #2503 merge; source audit proves `crates/drivers/drv/src/model.rs::unbind` reads `dev.bound()`, resolves the registered driver on the same bus, calls `driver.remove(dev)`, then clears `*dev.driver.lock() = None` and emits `BindEvent::Unbound`. Added hosted regression `unbind_calls_remove_before_clearing_binding`, whose test driver records that `remove` sees `dev.bound() == Some("unbind-order-test")` before unbind returns with `d.bound() == None`. Checks pass: `cargo test -p drv unbind_calls_remove_before_clearing_binding -- --nocapture`, `cargo test -p drv device_del_unbinds_bound_driver_once -- --nocapture`, and full `cargo test -p drv -- --nocapture --test-threads=1` with 27/27 tests. Pre-push boot-smoke PASS on both x86_64 and aarch64. |

## B447 Current

| Branch | Status | Evidence |
|---|---|---|
| B447-device-del-unbinds-first | VERIFIED | Fresh main `ffe736bc` after PR #2504 merge; source audit proves `crates/drivers/drv/src/model.rs::device_del` first confirms the device is registered, calls `unbind(d)` whenever `d.bound().is_some()`, then fires `SYSFS_REMOVE_HOOK`, then `DEVTMPFS_DEL_HOOK`, then drops the device from `DEVICES`. Focused hosted checks pass: `cargo test -p drv device_del_orders_remove_event_and_devtmpfs_teardown -- --nocapture` and `cargo test -p drv device_del_unbinds_bound_driver_once -- --nocapture`. Full hosted driver-model regression passes: `cargo test -p drv -- --nocapture --test-threads=1` with 27/27 tests. Runtime x86_64/aarch64 proof is inherited from B446 pre-push boot-smoke PASS because B447 changes only docs/metadata and production `device_del` code is unchanged. |

## B448 Current

| Branch | Status | Evidence |
|---|---|---|
| B448-device-del-remove-visible | VERIFIED | Fresh main `fa17ea74` after PR #2505 merge; source audit proves `crates/drivers/drv/src/model.rs::device_del` fires `SYSFS_REMOVE_HOOK` before `DEVICES.retain(...)` removes the object from the registry. Hosted hook `device_del_order_sysfs_remove` asserts `dev.bound() == None` and `devices().iter().any(|d| d.bus == dev.bus && d.addr == dev.addr)` while the remove hook runs. Checks pass: `cargo test -p drv device_del_orders_remove_event_and_devtmpfs_teardown -- --nocapture` and full `cargo test -p drv -- --nocapture --test-threads=1` with 27/27 tests. Runtime x86_64/aarch64 proof is inherited from B446 pre-push boot-smoke PASS because B448 changes only docs/metadata and production `device_del` code is unchanged. |

## B449 Current

| Branch | Status | Evidence |
|---|---|---|
| B449-device-del-devtmpfs-teardown | VERIFIED | Fresh main `8817dfc8` after PR #2506 merge; source audit proves `crates/drivers/drv/src/model.rs::device_del` clones `d.devname` and calls `DEVTMPFS_DEL_HOOK` with that owned name, `crates/kernel/kmain/src/kmain/early.rs` wires the hook to `devfs::del_device_node`, and `crates/kernel/devfs/src/lib.rs::del_device_node` maps the name to `/dev/<name>` then unregisters that subtree. Checks pass: `cargo test -p drv device_del_orders_remove_event_and_devtmpfs_teardown -- --nocapture`, `cargo test -p devfs add_device_node_creates_dev_entries -- --nocapture`, and full `cargo test -p drv -- --nocapture --test-threads=1` with 27/27 tests. Runtime x86_64/aarch64 proof is inherited from B446 pre-push boot-smoke PASS because B449 changes only docs/metadata and production devtmpfs teardown code is unchanged. |

## B450 Current

| Branch | Status | Evidence |
|---|---|---|
| B450-device-del-registry-drop-after-teardown | IN AUDIT | Fresh main `4df7512a` after PR #2507 merge; auditing that `device_del` removes the model device from the registry only after driver remove, sysfs remove, and devtmpfs teardown. |
