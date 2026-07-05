# Driver progress

Date: 2026-07-05

`driver_plan.md` is the status ledger. This file records current evidence and
blockers for the active row.

Current marker: B497-virtio-child-policy-only; IN AUDIT.

## B497 Current

| Branch | Status | Evidence |
|---|---|---|
| B497-virtio-child-policy-only | IN AUDIT | Fresh main `d93b3a4a` after PR #2556 merge; auditing that child virtio driver crates only provide profile, install, remove, and shutdown policy while generic wrapper/shared virtio/pci-boot own matching, session lifecycle, publish/release/remove/unpublish, and shutdown key lookup; hosted and x86_64/aarch64 smoke gates required before merge. |

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
