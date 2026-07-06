# Driver progress

Date: 2026-07-05

`driver_plan.md` is the status ledger. This file records current evidence and
blockers for the active row.

Current marker: none; B509-msix-function-mask-live-proof VERIFIED; next row not claimed yet.

## B509 Current

| Branch | Status | Evidence |
|---|---|---|
| B509-msix-function-mask-live-proof | VERIFIED | Branch restored from current `origin/main` (`035cbb3b`) after stale local B509 state was overwritten; `metadata/index.md` now claims B509 by advancing B 509 -> 510. Patch adds Linux-style MSI-X masked-enable/table-entry-readback/entry-unmask ordering, delayed function-mask clear after virtio queue programming/`DRIVER_OK`, arch-local MSI-X config helpers, ARM cache publication for ITS/LPI/virtqueue memory, rootfs staging/cache support for `OXIDE_MSIX_NET_RX_SMOKE`, and `/bin/msix_net_rx_probe` as the `driver-path-smoke.service` command. ARM failure was narrowed by rejected diagnostic-only runs to PCI-originated MSI routing: q0 received the ARP reply while `MSI_FIRES` did not change. Root cause fixed by programming the architectural ITS translation-frame doorbell (`GITS_TRANSLATER = ITS_BASE + 0x10040`) instead of the control-frame `0x0040`; QEMU readback now shows the net device MSI-X table targeting `msg_addr=0x8090040`. Temporary synthetic ITS and child-driver diagnostics were removed before final proof. Checks pass: `cargo check -q -p arch-irq -p firmware -p pci-boot -p virtio -p drv-virtio-net`; `git diff --check`; clean aarch64 smoke `/tmp/b509-arm-msix-net-rx-final.log` shows `msix_net_rx_probe: PASS rx=103 bytes from 10.0.2.3`; clean x86_64 smoke `/tmp/b509-x86-msix-net-rx-final.log` shows the same PASS. |

## B508 Current

| Branch | Status | Evidence |
|---|---|---|
| B508-msix-teardown-order | VERIFIED | Fresh main `c9e67dd0` after PR #2573 merge. `metadata/index.md` advanced B 508 -> 509. Added PCI-owned MSI-X constants, `msix_control_value`, and `emit_msix_teardown_steps` with hosted regressions for enable/disable bits and teardown ordering. `pci-boot` now releases bound MSI-X by masking all live table entries first, disabling each MSI-X capability once, freeing MSI IDs only after function disable, and then dropping PCI command memory/bus-master decode in the caller. Failed-probe devres now resets the device, releases MSI-X, disables PCI command, unmaps transport mappings, then frees probe frames. Checks pass: `cargo test -q -p pci -- --nocapture --test-threads=1` 14/14; broad hosted `pci-boot`/`virtio`/all virtio-child driver gate; `git diff --check`; touched files under line caps; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 34s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 38s. |

## B507 Current

| Branch | Status | Evidence |
|---|---|---|
| B507-virtio-child-transport-session-contract | VERIFIED | Fresh main `2658868e` after PR #2570 merge. `metadata/index.md` advanced B 507 -> 508. Removed `location()` from shared `virtio::VirtioChildTransportSession`; non-PCI probe-session tests no longer fabricate BDF-shaped location; shared `VirtioChildModelIdentity::modern` constructs child identities without PCI input. `pci-boot::VirtioChildSession` keeps `pci_bdf()` as a concrete PCI-wrapper method, and `VirtioChildOps::probe_child` receives BDF only inside the pci-boot wrapper; GPU still uses it for display metadata, while net/sound no longer consume PCI location. `drv-virtio-net` init/runtime state now uses only `VirtioChildDeviceKey` plus transport resources and removed its stale `pci` dependency. `drv-virtio-blk` debug output logs opaque child keys instead of decoding synthetic keys as BDF. Checks pass: `cargo test -q -p virtio -- --nocapture --test-threads=1` 44/44; `cargo test -q -p drv-virtio-net -- --nocapture --test-threads=1` 16/16; `cargo test -q -p drv-virtio-blk -- --nocapture --test-threads=1` 18/18; broad hosted driver gate for `pci-boot`, `virtio`, and all virtio child driver crates; `git diff --check`; touched Rust files remain under 500 lines; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 34s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 38s. |

## B506 Current

| Branch | Status | Evidence |
|---|---|---|
| B506-gpu-owner-key-boundary | VERIFIED | Fresh main `5755e327` after PR #2569 merge. Added typed DRM/fbdev callback keys: `drm::node::ScanoutDriverKey` and `fbdev::FbDriverKey`; `drv-virtio-gpu` converts from `VirtioChildDeviceKey` only at hook install and callback adapters, with BDF retained only as metadata/unique-string input. Private scanout helpers now consume `VirtioChildDeviceKey` instead of raw owner integers. Checks pass: `cargo test -q -p drm -p fbdev -- --nocapture --test-threads=1` with DRM 68/68 and fbdev 23/23; `cargo test -q -p drv-virtio-gpu -- --nocapture --test-threads=1` 36/36; broad hosted `cargo test -q -p pci-boot -p virtio -p drv-virtio-net -p drv-virtio-blk -p drv-virtio-rng -p drv-virtio-vsock -p drv-virtio-snd -p drv-virtio-input -p drv-virtio-gpu -- --nocapture --test-threads=1` with child suites 18/18, 36/36, 36/36, 16/16, 8/8, 8/8, 7/7, shared `virtio` 43/43, and pci-boot compile-only 0 tests; `git diff --check`; touched Rust files remain at or under 500 lines (`drm/src/dumb/tests.rs` 500, `drm/src/node/tests.rs` 496, `drv-virtio-gpu/src/post_init/scanout.rs` 423, `runtime.rs` 105, `fbdev/src/registry.rs` 263); `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 54s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 58s. |

## B505 Current

| Branch | Status | Evidence |
|---|---|---|
| B505-sound-owner-key-boundary | VERIFIED | Fresh main `269e02a2` after PR #2567 merge. Added `sound::SoundOwnerKey`, a sound-owned nonzero owner identity, and moved sound card reservations, ALSA card lookup/removal, sound ops bindings, `SndData`, PCM/capture/OSS state, and `SoundOps` callbacks from raw `u32` to typed owner keys. `drv-virtio-snd::sound_owner` now converts `VirtioChildDeviceKey` to `Option<sound::SoundOwnerKey>` once before install/uninstall and callback context lookup, keeping sound-core independent of virtio. Checks pass: `cargo test -q -p sound -- --nocapture --test-threads=1` 16/16; `cargo test -q -p drv-virtio-snd -- --nocapture --test-threads=1` 8/8; broad hosted `cargo test -q -p pci-boot -p virtio -p drv-virtio-net -p drv-virtio-blk -p drv-virtio-rng -p drv-virtio-vsock -p drv-virtio-snd -p drv-virtio-input -p drv-virtio-gpu -- --nocapture --test-threads=1` with child suites 18/18, 36/36, 36/36, 16/16, 8/8, 8/8, 7/7, shared `virtio` 43/43, and pci-boot compile-only 0 tests; `git diff --check`; touched Rust files remain under 500 lines (`sound/src/tests.rs` 491, `drv-virtio-snd/src/tests.rs` 354, `lifecycle.rs` 235, `cards.rs` 155, `ops.rs` 123); `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 34s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 38s. |

## B504 Current

| Branch | Status | Evidence |
|---|---|---|
| B504-vsock-owner-key-boundary | VERIFIED | Fresh main `b2251d0a` after PR #2564 merge. Added `net::vsock::VsockOwner`, a transport-neutral nonzero owner type, and moved wildcard bind/listen state to `Option<VsockOwner>` instead of raw owner `0`. `net::vsock` driver APIs, TX/RX hooks, endpoint lookup, connection keys, and listener tables now consume typed owners; `drv-virtio-vsock` converts `VirtioChildDeviceKey` through one local `vsock_owner` helper before reserve/publish/uninstall/quiesce and receives typed owner callbacks. Kernel-only `sys_connect` path was fixed from raw `0` to `None` after x86 smoke compile caught it. Checks pass: focused `cargo test -q -p net vsock -- --nocapture --test-threads=1` 28/28; `cargo test -q -p drv-virtio-vsock -- --nocapture --test-threads=1` 7/7; broad hosted `cargo test -q -p pci-boot -p virtio -p drv-virtio-net -p drv-virtio-blk -p drv-virtio-rng -p drv-virtio-vsock -p drv-virtio-snd -p drv-virtio-input -p drv-virtio-gpu -- --nocapture --test-threads=1` with child suites 18/18, 36/36, 36/36, 16/16, 8/8, 8/8, 7/7, shared `virtio` 43/43, and pci-boot compile-only 0 tests; `git diff --check`; touched Rust files remain under 500 lines (`vsock/mod.rs` 489, `vsock/conn.rs` 355, `vsock_socket.rs` 301, `registry.rs` 263, `tx.rs` 60, `rx.rs` 145); `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 42s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 38s. |

## Next Audit Prep

| Branch | Status | Evidence |
|---|---|---|
| B508-next-driver-row | PENDING | Claim next unverified row only after B507 commit, PR, merge, and fresh `main` sync. Use `metadata/index.md` before opening the branch. Fanout audits found next MSI-X teardown and `VirtioProbeState` ownership rows are still `NOT DONE`, while MSI-X function-mask clearing is `SOURCE OK` but lacks live interrupt proof; vsock and sound ownership rows are `SOURCE OK` but need hosted fault-injection proof before `VERIFIED`. |

## B503 Current

| Branch | Status | Evidence |
|---|---|---|
| B503-transport-neutral-child-key-proof | VERIFIED | Fresh main `56e4935e` after PR #2561 merge. B502 is occupied by local unmerged branch `B502-fifo-open-impl` at `128b8e08`, so this driver lane uses B503 and advances the B counter to B504. Code change removes BDF-derived child runtime keys: shared virtio adds child-address key construction from `virtioN` with nonzero one-based raw keys; `VirtioChildSession` stores `device_key` from `dev.addr`; `parent_key` parses the child device address instead of parent PCI BDF; `VirtioPciTransport::publish` passes the child key to devres; persistent PCI transport records are looked up by `VirtioChildDeviceKey` while retaining BDF only for MSI-X/MMIO teardown. Non-PCI proof: `child_device_key_is_constructed_from_child_model_address` derives a key from `VirtioChildModelIdentity` without `VirtioTransportLocation`, maps `virtio0` to raw key 1, and rejects non-virtio/malformed addresses. Checks pass: focused non-PCI key test 1/1; broad hosted `cargo test -q -p pci-boot -p virtio -p drv-virtio-net -p drv-virtio-blk -p drv-virtio-rng -p drv-virtio-vsock -p drv-virtio-snd -p drv-virtio-input -p drv-virtio-gpu -- --nocapture --test-threads=1` with child suites 18/18, 36/36, 36/36, 16/16, 8/8, 8/8, 7/7, shared `virtio` 43/43, and pci-boot compile-only 0 tests; first x86 smoke attempt exposed and fixed a `pci-boot` import-boundary compile error; final `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 30s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 36s. |

## B501 Current

| Branch | Status | Evidence |
|---|---|---|
| B501-pci-backed-child-wrapper-descriptors | VERIFIED | Fresh main `b9fd51db` after PR #2560 merge. Source audit proves the PCI-backed child wrapper consumes child driver descriptors for all wrapper-facing identity and profile paths: `VirtioChildOps::DRIVER_ID` is the descriptor contract, `VirtioChildDriver<O>::name` returns `O::DRIVER_ID.name`, `matches` delegates to `O::DRIVER_ID.matches_device(&dev.bus, dev.vendor_id, dev.device_id)`, `probe` begins the session with `O::profile()`, and each GPU/Input/Net/Block/RNG/Vsock/Sound ops adapter sets `DRIVER_ID` and `profile` from child crate exports. `register_model_drivers` registers typed `VirtioChildDriver<Ops>` statics; source search finds no wrapper-local `VirtioChildDriverId::new` or child `device_id` literals in `pci-boot::virtio_child`. Checks pass: `cargo test -q -p pci-boot -p virtio -p drv-virtio-net -p drv-virtio-blk -p drv-virtio-rng -p drv-virtio-vsock -p drv-virtio-snd -p drv-virtio-input -p drv-virtio-gpu -- --nocapture --test-threads=1` with child suites 18/18, 36/36, 36/36, 16/16, 8/8, 8/8, 7/7, shared `virtio` 43/43, and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 14s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 16s. |

## B500 Current

| Branch | Status | Evidence |
|---|---|---|
| B500-virtio-child-descriptor-exports | VERIFIED | Fresh main `37e7b2ff` after PR #2559 merge. Source audit proves each virtio child driver crate exports its own descriptor/profile surface: GPU re-exports `wire::*` for `DRIVER_ID` and `device::*` for `transport_profile`; Input re-exports `consts::*`; RNG and Vsock re-export `consts::{transport_profile, wanted_features, DRIVER_ID, ...}`; Sound defines `pub const DRIVER_ID` and `pub const fn transport_profile` at crate root; Net and Block expose `modern::DRIVER_ID` and `modern::transport_profile` from public `modern` modules. `pci-boot::virtio_child` consumes only those child exports for GPU/Input/Net/Block/RNG/Vsock/Sound ops adapters. Checks pass: `cargo test -q -p pci-boot -p virtio -p drv-virtio-net -p drv-virtio-blk -p drv-virtio-rng -p drv-virtio-vsock -p drv-virtio-snd -p drv-virtio-input -p drv-virtio-gpu -- --nocapture --test-threads=1` with child suites 18/18, 36/36, 36/36, 16/16, 8/8, 8/8, 7/7, shared `virtio` 43/43, and pci-boot compile-only 0 tests; child driver source files remain under 500 lines; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 15s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 16s. |

## B499 Current

| Branch | Status | Evidence |
|---|---|---|
| B499-virtio-gpu-placeholder-notify | VERIFIED | Fresh main `039d8a21` after PR #2558 merge. Source audit finds no production `placeholder`/stub notify marker in `crates/drivers/drv-virtio-gpu`; production GPU display probe and scanout command submission write queue indexes to `ctrlq.notify_va` from transport-supplied `virtio::VirtQueueResource`; shared `VirtQueueResource::is_runtime_valid` requires nonzero `notify_va`; pci-boot maps notify addresses through `virtio::notify_pa` from the virtio-pci NOTIFY cap, `map_queue_notify_va`, and `resolve_planned_notify_mappings`; shared handoff builds child queue resources with those mapped notify VAs. Zero `notify_va` literals in GPU are test/support fixtures only. Checks pass: `cargo test -q -p pci-boot -p virtio -p drv-virtio-gpu -- --nocapture --test-threads=1` with GPU 36/36, shared `virtio` 43/43, and pci-boot compile-only 0 tests; GPU source files remain under 500 lines (`tests.rs` 477, `scanout.rs` 422, `wire.rs` 414, `device.rs` 380); `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 12s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 16s. |

## B498 Current

| Branch | Status | Evidence |
|---|---|---|
| B498-virtio-child-device-ids | VERIFIED | Fresh main `083201b1` after PR #2557 merge. Source audit proves net/block/RNG/vsock/sound/input/GPU child crates own their virtio child device ID constants and `DRIVER_ID` descriptors: `drv-virtio-net::modern::VIRTIO_ID_NET = 1`, `drv-virtio-blk::modern::VIRTIO_ID_BLOCK = 2`, `drv-virtio-rng::VIRTIO_ID_RNG = 4`, `drv-virtio-gpu::VIRTIO_ID_GPU = 16`, `drv-virtio-input::VIRTIO_ID_INPUT = 18`, `drv-virtio-vsock::VIRTIO_ID_VSOCK = 19`, and `drv-virtio-snd::VIRTIO_ID_SOUND = 25`; shared `virtio::VirtioChildDriverId::new` carries the descriptor and `matches_device` checks virtio bus, Red Hat virtio vendor, and exact child device ID; `pci-boot::virtio_child` ops adapters set `O::DRIVER_ID` from the child crate constants and source search finds no wrapper-local numeric child `device_id` literals. Checks pass: `cargo test -q -p pci-boot -p virtio -p drv-virtio-net -p drv-virtio-blk -p drv-virtio-rng -p drv-virtio-vsock -p drv-virtio-snd -p drv-virtio-input -p drv-virtio-gpu -- --nocapture --test-threads=1` with child suites 18/18, 36/36, 36/36, 16/16, 8/8, 8/8, 7/7, shared `virtio` 43/43, and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 12s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 17s. |

## B497 Current

| Branch | Status | Evidence |
|---|---|---|
| B497-virtio-child-policy-only | VERIFIED | Fresh main `d93b3a4a` after PR #2556 merge. Source audit proves child virtio driver crates only supply profile, install/init, remove/uninstall, and shutdown policy: the only bus-facing child `drv::Driver` implementation, driver registration, matching, probe/remove/shutdown wrapper, parent-key lookup, transport session lifecycle, publish, failed-probe release, remove-unpublish, and shutdown-key dispatch live in `crates/kernel/pci-boot/src/virtio_child.rs` and shared `crates/drivers/virtio/src`; GPU/input/net/block/RNG/vsock/sound crates export `DRIVER_ID`, `transport_profile`, install/init, remove/uninstall, and shutdown entrypoints, and source search finds no child crate `drv::Driver`, `drv::register_driver`, bind/unbind, pci-boot transport import, `VirtioPciTransport`, `VirtioChildSession`, or shared `run_child_*` lifecycle call. Checks pass: `cargo test -q -p pci-boot -p virtio -p drv-virtio-net -p drv-virtio-blk -p drv-virtio-rng -p drv-virtio-vsock -p drv-virtio-snd -p drv-virtio-input -p drv-virtio-gpu -- --nocapture --test-threads=1`; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 12s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 16s. |

## B496 Current

| Branch | Status | Evidence |
|---|---|---|
| B496-virtio-child-shutdown-key | VERIFIED | Fresh main `c0b2c792` after PR #2555 merge. Source audit proves child shutdown resolves the stable parent-derived child key through the centralized wrapper path and only invokes child shutdown policy: generic `VirtioChildDriver<O>::shutdown` calls `parent_key(dev)` and shared `virtio::run_child_shutdown(device_key, O::shutdown_child)`; `parent_key` derives the `VirtioChildDeviceKey` from the parent PCI model device; GPU/input/net/block/RNG/vsock/sound child ops adapters receive only that key and call their explicit shutdown callbacks. Checks pass: `cargo test -q -p virtio child_shutdown_lifecycle_passes_stable_key -- --nocapture --test-threads=1` 1/1; `cargo test -q -p pci-boot -p virtio -- --nocapture --test-threads=1` with virtio 43/43 and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 12s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 16s. |

## B495 Current

| Branch | Status | Evidence |
|---|---|---|
| B495-virtio-child-remove-unpublish | VERIFIED | Fresh main `01fec269` after PR #2554 merge. Source audit proves child remove uses the centralized parent-key path and unpublishes transport state after child policy remove: generic `VirtioChildDriver<O>::remove` calls `parent_key(dev)` and then shared `virtio::run_child_remove(device_key, O::remove_child, unpublish_transport)`; `parent_key` derives the stable `VirtioChildDeviceKey` from the parent PCI model device; `run_child_remove` calls child remove first and transport unpublish second; pci-boot `unpublish_transport` routes through `VirtioPciTransport::unpublish_key` to `unpublish_transport_record`, releasing the persistent transport record. Checks pass: `cargo test -q -p virtio child_remove_lifecycle_removes_before_unpublish -- --nocapture --test-threads=1` 1/1; `cargo test -q -p pci-boot -p virtio -- --nocapture --test-threads=1` with virtio 43/43 and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 12s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 16s. |

## B494 Current

| Branch | Status | Evidence |
|---|---|---|
| B494-virtio-child-success-publish | VERIFIED | Fresh main `5ce39617` after PR #2553 merge. Source audit proves successful child probes publish transport-owned runtime state only through the centralized wrapper/session path: shared `virtio::run_child_probe` calls `session.publish()` only after child `probe` returns `Ok(())`; pci-boot `VirtioChildSession::publish` consumes the live transport lease before calling `VirtioPciTransport::publish`; `publish_transport_mmio` delegates to `VirtioProbeDevres::publish`, which one-shot transfers mappings, vring frames, and MSI-X bindings into `publish_transport_record`. Checks pass: `cargo test -q -p virtio child_probe_lifecycle_publishes_only_after_success -- --nocapture --test-threads=1` 1/1; `cargo test -q -p pci-boot -p virtio -- --nocapture --test-threads=1` with virtio 43/43 and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 12s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 16s. |

## B493 Current

| Branch | Status | Evidence |
|---|---|---|
| B493-virtio-child-failed-probe-release | VERIFIED | Fresh main `cc4fca3c` after PR #2551 merge. Source audit proves failed child probes release transport-owned probe state through the centralized wrapper/session path: `virtio::run_child_probe` calls `session.release_failed_child()` on child probe errors and publishes only on success; `VirtioChildSession::release_failed_child` consumes the transport lease and calls pci-boot failed-child release; session `Drop` covers early exits; pci-boot `VirtioProbeDevres` one-shot release resets the device, frees frames, releases MSI-X bindings, disables PCI command, and unmaps mappings. Checks pass: `cargo test -q -p virtio child_probe_lifecycle_releases -- --nocapture --test-threads=1` 2/2; `cargo test -q -p pci-boot -p virtio -- --nocapture --test-threads=1` with virtio 43/43 and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 34s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 38s. |

## B492 Current

| Branch | Status | Evidence |
|---|---|---|
| B492-virtio-child-session-begin | VERIFIED | Fresh main `4675c773` after PR #2549 merge. Source audit proves child probe session setup is centralized in the wrapper: the only child wrapper `probe` calls `VirtioChildSession::begin(dev, O::profile())?` and then `virtio::run_child_probe(session, |session| O::probe_child(session))`; `VirtioChildSession::begin` owns parent PCI lookup, `VirtioPciTransport::probe_child` acquisition, probe tracing, child address capture, profile storage, and live `VirtioProbeLease` setup before any child-specific policy runs; child crates only receive `&mut dyn VirtioChildTransportSession`. Checks pass: `cargo test -q -p virtio child_probe_lifecycle -- --nocapture --test-threads=1` 3/3; `cargo test -q -p pci-boot -p virtio -- --nocapture --test-threads=1` with virtio 43/43 and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 12s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 16s. |

## B491 Current

| Branch | Status | Evidence |
|---|---|---|
| B491-virtio-child-device-id-matching | VERIFIED | Fresh main `60b781a1` after PR #2548 merge. Source audit proves child matching is centralized through shared virtio child device IDs: `virtio::VirtioChildDriverId::matches_device` requires `VIRTIO_CHILD_BUS`, `VIRTIO_VENDOR_ID`, and exact `device_id`; `VirtioChildDriver<O>::matches` delegates directly to `O::DRIVER_ID.matches_device(&dev.bus, dev.vendor_id, dev.device_id)`; GPU/input/net/blk/rng/vsock/snd child crates export named `DRIVER_ID` descriptors with their virtio device IDs; search finds no child crate bus-facing `drv::Driver` match implementation. Checks pass: `cargo test -q -p virtio child_driver_id_matches_virtio_child_devices -- --nocapture --test-threads=1` 1/1; `cargo test -q -p pci-boot -p virtio -- --nocapture --test-threads=1` with virtio 43/43 and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 12s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 16s. |

## B490 Current

| Branch | Status | Evidence |
|---|---|---|
| B490-virtio-child-single-bus-facing-wrapper | VERIFIED | Fresh main `458afcd1` after PR #2547 merge. Source audit proves virtio child binding is driven by one generic bus-facing `VirtioChildDriver<O>` wrapper: `virtio_child.rs` owns the single child `impl<O: VirtioChildOps> drv::Driver for VirtioChildDriver<O>`, supplies `virtio::VIRTIO_CHILD_BUS`, generic `O::DRIVER_ID` matching, and `VirtioChildSession::begin`/`virtio::run_child_probe`; GPU/input/net/blk/rng/vsock/snd registrations are typed wrapper statics; the only other virtio `drv::Driver` impl is parent PCI transport `VirtioPciDrv`; child driver crates do not implement bus-facing `drv::Driver`. Checks pass: `cargo test -q -p pci-boot -p virtio -- --nocapture --test-threads=1` with virtio 43/43 and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 30s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 34s. |

## B489 Current

| Branch | Status | Evidence |
|---|---|---|
| B489-child-probes-no-transport-callback-imports | VERIFIED | Fresh main `135f7977` after PR #2546 merge. Source audit proves child crates do not import PCI transport helper callbacks such as `VirtioPciTransport`, `VirtioPciAcquisition`, `VirtioProbe`, `bind_msix_vector`, queue programming, or transport MMIO publish/unpublish helpers; child probes consume `VirtioChildTransportSession` plus child crate profile/install/remove/shutdown APIs; the only transport cleanup callback is centralized in `virtio_child.rs` remove handling through `virtio::run_child_remove`; stale child-crate comments naming `pci_boot::virtio_drv` were replaced with generic transport-backend wording. Checks pass: `cargo test -q -p pci-boot -p virtio -- --nocapture --test-threads=1` with virtio 43/43 and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 30s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 35s. |

## B488 Current

| Branch | Status | Evidence |
|---|---|---|
| B488-pci-transport-no-child-driver-decls | VERIFIED | Fresh main `3c0c2b61` after PR #2545 merge. Source audit/search over `crates/kernel/pci-boot/src/virtio_drv`, `virtio_transport`, and `virtio_child.rs` proves the PCI transport files contain only `VirtioPciDrv`, `impl drv::Driver for VirtioPciDrv`, and `VIRTIO_PCI_DRV`; every child `VirtioChildDriver` static, `Virtio*Ops` adapter, and child `drv::register_driver(&VIRTIO_*_DRV)` call lives in `virtio_child.rs`; `virtio_drv::driver::register_model_drivers` registers only `VIRTIO_PCI_DRV` before delegating to `virtio_child::register_model_drivers`. Checks pass: `cargo test -q -p pci-boot -p virtio -- --nocapture --test-threads=1` with virtio 43/43 and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 12s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 16s. |

## B487 Current

| Branch | Status | Evidence |
|---|---|---|
| B487-virtio-child-declarations-split | VERIFIED | Fresh main `349bba3e` after PR #2544 merge. Source audit proves `crates/kernel/pci-boot/src/virtio_child.rs` owns `VirtioChildDriver<O>`, every child `Virtio*Ops` adapter, static child declarations for net/blk/rng/vsock/snd/input/gpu, and the child `drv::register_driver` list; `virtio_drv::driver` owns only the `VIRTIO_PCI_DRV` PCI transport model driver, publishes child model devices, and delegates child registration to `virtio_child::register_model_drivers`; search finds no child `drv::Driver` static declarations in `virtio_drv` or `virtio_transport`. Checks pass: `cargo test -q -p pci-boot -p virtio -- --nocapture --test-threads=1` with virtio 43/43 and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 12s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 16s. |

## B486 Current

| Branch | Status | Evidence |
|---|---|---|
| B486-virtio-child-drivers-model-bind | VERIFIED | Fresh main `d2657a13` after PR #2543 merge. Source audit proves `pci-boot::register_pci_model_drivers` reaches `virtio_drv::register_model_drivers`, which registers `VIRTIO_PCI_DRV` and all child wrappers through `drv::register_driver`; `VirtioChildDriver<O>` exposes the virtio child bus/name/matches/probe bridge and routes successful matches through `VirtioChildSession::begin` plus `virtio::run_child_probe`; search finds no direct child `drv::bind`/`bind_addr` bypass, only child subsystem publications such as hwrng/devfs. Checks pass: `cargo test -q -p virtio child_driver_id_matches_virtio_child_devices -- --nocapture --test-threads=1` 1/1; `cargo test -q -p pci-boot -p virtio -- --nocapture --test-threads=1` with virtio 43/43 and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 12s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 16s. |

## B485 Current

| Branch | Status | Evidence |
|---|---|---|
| B485-virtio-child-fallible-publication | VERIFIED | Fresh main `bc9921df` after PR #2542 merge; merged as PR #2543 at `d2657a13`. Source audit proves `VirtioPciDrv::probe` maps modern PCI identity through `VirtioChildModelIdentity::modern_from_pci`, publishes the child with `drv::try_device_add(Arc::new(drv::Device::new(...).with_parent("pci", ...)))?`, and relies on driver-core to invoke child `VirtioChildDriver::probe`; `run_child_probe` publishes transport state only after child success and releases failed probe resources on error/drop. Checks pass: `cargo test -q -p virtio child_probe_lifecycle -- --nocapture --test-threads=1` 3/3; `cargo test -q -p pci-boot -p virtio -- --nocapture --test-threads=1` with virtio 43/43 and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 28s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 34s. |

## B484 Current

| Branch | Status | Evidence |
|---|---|---|
| B484-msix-programming-virtio-transport | VERIFIED | Fresh main `760826fe` after PR #2541 merge; merged as PR #2542 at `bc9921df`. Tightened `virtio_transport` re-export to `pub(super)` while keeping the private `msix` child as the only MSI-X table/config programming owner. Source audit/search proves the only live `bind_msix_vector` caller is `virtio_drv::probe`, `set_msix_enabled_arch` and MSI-X table writes stay in `virtio_transport::msix`, and child driver crates only supply profiles/handlers. Checks pass: `cargo test -q -p pci-boot -p virtio -- --nocapture --test-threads=1` with virtio 43/43 and pci-boot compile-only 0 tests; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 28s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 34s. |

## B483 Current

| Branch | Status | Evidence |
|---|---|---|
| B483-pci-msix-capability-readonly-audit | VERIFIED | Fresh main `d18bf28b` after PR #2540 merge; merged as PR #2541 at `760826fe`. Source audit proves `pci::capabilities` and `pci::decode_msix_cap` only use config-space reads, `pci-boot::trace` logs MSI-X metadata without programming device state, and MSI-X table writes stay isolated in virtio-pci transport bind/release. Added regression `capability_walk_and_msix_decode_do_not_write_config_space`. Checks pass: `cargo test -p pci capability_walk_and_msix_decode_do_not_write_config_space -- --nocapture --test-threads=1`; `cargo test -q -p pci -p pci-boot -- --nocapture --test-threads=1`; `OXIDE_SKIP_ROOTFS=1 make smoke-x86 SMOKE_TIMEOUT=300` reached `oxide login:` in 12s; `OXIDE_SKIP_ROOTFS=1 make smoke-arm SMOKE_TIMEOUT=300` reached `oxide login:` in 16s. |

## Archived Progress

Rows older than B483 are compacted here to keep this active progress file under
the repo markdown cap. `driver_plan.md` remains the authoritative full ledger
for every item, branch, description, and current status.
