# Driver progress

Date: 2026-07-05

`driver_plan.md` is the status ledger. This file records current evidence and
blockers for the active row.

Current marker: B488-pci-transport-no-child-driver-decls; VERIFIED pending PR merge.

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
