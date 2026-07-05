# Driver plan

Date: 2026-07-05

ACTIVE NOW: none; B442-add-uevent-driver-state VERIFIED pending PR merge.

Current active item: none; next claim starts after B442 merge and fresh main
sync.

Next gate after merge: return to fresh `origin/main` before claiming B443 using
`metadata/index.md`.

Scope: working audit ledger for every driver-system item carried by
`driver_anal.md`. `driver_progress.md` records current evidence and test
results; this file is the task table to revisit item-by-item until Linux
compliance is proven.

Status legend:

- `NOT DONE`: default state; row has not yet been freshly proven from current source and required runtime evidence.
- `ACTIVE`: row is the current branch target; status text records latest arch gate.
- `IN AUDIT`: row is actively being checked on the named branch.
- `SOURCE OK`: current source proves the implementation shape, but runtime/Linux compliance proof may still be needed.
- `VERIFIED`: current source plus appropriate hosted/QEMU/userspace evidence proves the row.
- `BLOCKED`: current evidence shows a dependency or missing subsystem prevents completion.
- `OBSOLETE`: row is an old baseline claim contradicted by current source and no longer a required fix.

| Status | Branch | Description |
|---|---|---|
| SOURCE OK | B001-userspace-discovery-model-owned | Userspace discovery must see model-owned `/dev`, `/sys`, class, `dev`, `/sys/dev`, and uevent state for GNOME/systemd/udev/logind/libinput/Mesa/ALSA; no kernel userspace-policy shortcuts. |
| VERIFIED | B002-single-machine-desktop-proof | Single-machine desktop path must be proven for one virtio GPU, one input stack, one sound card, one root disk, and one network device. |
| VERIFIED | B326-userspace-seat-driver-proof | Fast driver-system proof for DRM/fbdev nodes, evdev nodes, ALSA nodes, block/net discovery, and uevent delivery on x86_64 and aarch64; `../oxide-images` GNOME remains final seat gate only. |
| NOT DONE | TBD | After single-device desktop works, expand fault injection, hotplug stress, and multi-device hardening. |
| VERIFIED | B425-no-flat-driverentry-probeall | Old flat `DriverEntry` / `probe_all(bdf)` live driver path is absent from current source: `rg` over `crates/`, `userspace/`, and `tools/` finds no live `DriverEntry` or `probe_all` symbols, and `crates/drivers/drv/src/model.rs` is the authoritative registry/bind/probe path. `cargo test -p drv -- --nocapture --test-threads=1` passes 24/24. |
| VERIFIED | B426-drv-model-authoritative-proof | `drv::Device`, `drv::Driver`, `try_device_add`, `device_del`, `bind`, `bind_addr`, and `unbind` are authoritative in `crates/drivers/drv/src/model.rs`: `drv/src/lib.rs` re-exports the model API, production driver/sysfs/devfs/block/sound/DRM call sites route through these functions, no public `auto_bind`/`register_device`/infallible `device_add` bypass remains, and `cargo test -p drv -- --nocapture --test-threads=1` passes 24/24. |
| VERIFIED | B427-no-public-auto-bind | Public `drv::auto_bind` is removed; automatic attachment is internal to `try_device_add` and `register_driver`: source search finds no `auto_bind` API, `try_device_add` calls private `attach_device_to_registered_drivers`, `register_driver` calls private `attach_driver_to_existing_devices`, both helpers call private `bind_inner`, focused auto-attach/no-initial-bind-change tests pass, and full `cargo test -p drv -- --nocapture --test-threads=1` passes 24/24. |
| VERIFIED | B428-sysfs-explicit-bind-route | Explicit binds route through sysfs driver `bind`: `/sys/bus/<bus>/drivers/<driver>/bind` parses the device address and calls `drv::bind_addr(bus, addr, driver)`, `unbind` resolves the currently bound model device and calls `drv::unbind`, driver directory links reflect bound model state, duplicate binds return `Ebusy`, and focused sysfs regressions `driver_bind_unbind_attrs_drive_drv_model` plus `bind_unbind_emit_change_uevents_from_current_model_state` pass. |
| VERIFIED | B429-pci-model-bar-publication | PCI enumeration creates `pci` model devices with BAR resources through fallible model publication: `pci-boot` maps per-arch BAR probes into `drv::Resource` records, publishes `drv::Device::new("pci", ...)` through `drv::try_device_add`, preserves matching duplicate identities without replacing the registry record, and hosted tests prove PCI BAR sizing, model resource preservation, duplicate rejection, sysfs `resourceN` exposure, plus x86_64/aarch64 fast driver-path smokes. |
| VERIFIED | B430-pci-model-driver-registration | NVMe, AHCI, and virtio-pci register as PCI model drivers: `pci-boot` registers `drv_nvme::NVME_DRIVER`, `drv_ahci::AHCI_DRIVER`, and the `virtio-pci` model driver before publishing enumerated PCI devices; `uevent_probe` now proves `/sys/bus/pci/drivers/{nvme,ahci,virtio-pci}` are live with bound devices on x86_64 and aarch64 fast driver-path smokes. |
| VERIFIED | B431-pci-driver-core-attach | PCI drivers attach through driver core, not enumeration-local direct bind calls: `pci-boot::enumerate_and_log` registers model drivers, publishes each PCI model device through `publish_pci_model_device`/`drv::try_device_add`, and source audit finds no `drv::bind`, `drv::bind_addr`, NVMe/AHCI init, or virtio child direct-probe call in PCI enumeration; B430 x86_64/aarch64 runtime logs prove resulting PCI driver bindings. |
| VERIFIED | B432-pci-publication-idempotent-proof | PCI model-device publication is fallible and idempotent for repeated matching `(pci, addr)` enumeration: `publish_pci_model_device` publishes through `drv::try_device_add`, returns the existing record only for matching bus/addr/vendor/device/class on `Busy`, and duplicate/mismatch regressions prove repeated publication does not replace registry state or bind the wrong identity. |
| VERIFIED | B421-pci-identity-mismatch-proof | PCI identity mismatch handling does not rebound a mismatched same-address function: hosted regression covers duplicate PCI addresses on bus 0 and bus 1 forms with different vendor/device/class, proves the original device remains bound, registry identity is not replaced, and the mismatched driver never probes. `cargo test -p drv pci_identity_mismatch_does_not_replace_or_rebind -- --nocapture`, full serial `cargo test -p drv -- --nocapture --test-threads=1`, and fast x86_64/aarch64 driver-path smokes pass with logs `/tmp/b421-pci-identity-mismatch-x86.log` and `/tmp/b421-pci-identity-mismatch-arm.log`. |
| VERIFIED | B433-model-binding-rejects-bound-devices | Model binding rejects already-bound devices: `bind_inner` returns `drv::Error::AlreadyBound` before driver lookup, match, or probe when `dev.bound()` is already set; automatic attach loops skip bound devices; sysfs maps `AlreadyBound` to `EBUSY`; focused model/sysfs tests and full driver-model tests pass, with x86_64/aarch64 runtime inherited from unchanged merged fast driver-path smokes. |
| VERIFIED | B434-model-binding-bus-driver-match | Model binding verifies bus/driver matching: `match_driver`, `find_driver_on_bus`, and `driver_matches_device` require bus equality before matching/override/bind; `bind_inner` rejects same-bus non-matching devices with `NoMatch`; hosted regressions cover bus-scoped driver names, wrong-bus bind rejection, driver override bus scoping, and same-bus ID mismatch without binding; pre-push boot smoke passed on x86_64 and aarch64. |
| VERIFIED | B435-model-binding-calls-probe | Model binding calls `Driver::probe`: `bind_inner` invokes `driver.probe(dev)?` after already-bound, bus, and match validation and before storing `dev.driver`; hosted probe counters prove auto-attach, explicit bind retry, failed-probe retry, and add-event ordering paths all execute the probe hook. |
| VERIFIED | B436-model-binding-records-after-probe | Model binding records binding only after successful probe: `bind_inner` uses fallible `driver.probe(dev)?` before assigning `dev.driver`, successful probe paths show bound state, failed probe paths leave devices unbound and retriable, and add-event ordering sees the bound state only after successful probe. |
| VERIFIED | B437-probe-failure-unbound-retriable | Probe failure leaves device unbound and retriable: `bind_inner` propagates `Driver::probe` failure before recording binding state, and hosted regression proves auto-probe plus repeated explicit bind attempts each increment the failing probe counter while `dev.bound()` remains `None`. |
| VERIFIED | B438-driver-registration-attaches-existing | Driver registration attaches newly registered drivers to existing unbound matching devices: `register_driver` publishes the driver then calls `attach_driver_to_existing_devices`, which skips bound/non-matching devices and calls `bind_inner` for existing unbound matches; hosted tests prove late registration binds once and duplicate registration does not reprobe. |
| VERIFIED | B439-driver-unregistration-detaches-bound | Driver unregistration detaches devices bound to that driver before removing the driver from registry: `unregister_driver` walks bound devices and calls `unbind` while the driver is still registered, then removes the driver entry; hosted regression proves remove callback, cleared binding, disappearing driver name, and later bind failure. |
| VERIFIED | B440-new-device-attach-after-publication | New model device attaches to already registered matching drivers after devtmpfs/sysfs publication setup and before add uevent: `try_device_add` publishes the model record, fires devtmpfs publication, auto-attaches with bind-change events suppressed, then fires sysfs add; hosted tests prove ordering and add uevent `DRIVER=` state. |
| VERIFIED | B441-initial-autoprobe-no-bind-change | Initial auto-probe does not emit a separate bind-change event before add uevent: `try_device_add` passes `emit_bind_event=false` into initial auto-attach, and hosted bind-hook regression proves initial probe binds the device while `ADD_BIND_EVENTS` remains zero before the sysfs add event. |
| VERIFIED | B442-add-uevent-driver-state | Add uevent carries current `DRIVER=<name>` state: `dev_uevent_env` appends `DRIVER=` only from `dev.bound()`, sysfs add/remove/change hooks emit the current model-derived environment, hosted add-uevent regression proves initial bound devices emit `ACTION=add` with `DRIVER=`, and hosted bind/unbind regression proves change events add `DRIVER=` when bound and omit stale driver state after unbind. |
| SOURCE OK |  | Boot-time platform serial devices rely on model-owned attach path. |
| SOURCE OK |  | Boot-time i8042 platform device relies on model-owned attach path. |
| SOURCE OK |  | Production explicit bind entry remains sysfs `/sys/bus/*/drivers/*/bind`. |
| SOURCE OK |  | Model unbind calls `Driver::remove` before clearing binding. |
| SOURCE OK |  | `device_del` unbinds first. |
| SOURCE OK |  | `device_del` emits remove while object is still visible. |
| SOURCE OK |  | `device_del` removes devtmpfs state. |
| SOURCE OK |  | `device_del` drops device from registry after remove/devtmpfs teardown. |
| SOURCE OK |  | Driver-core tests assert remove/sysfs/devtmpfs/registry disappearance order. |
| SOURCE OK |  | `drv::shutdown_all` walks bound model devices in reverse registration order. |
| SOURCE OK |  | `drv::shutdown_all` calls `Driver::shutdown` without unbinding or emitting remove events. |
| SOURCE OK | TBD | Power/reboot/halt path must call driver shutdown hook before restart/poweroff/halt. |
| SOURCE OK |  | NVMe has explicit shutdown callback. |
| SOURCE OK |  | AHCI has explicit shutdown callback. |
| SOURCE OK |  | virtio-pci has explicit shutdown callback. |
| SOURCE OK |  | virtio-blk has explicit shutdown callback. |
| SOURCE OK |  | virtio-input has explicit shutdown callback. |
| SOURCE OK |  | virtio-gpu has explicit shutdown callback. |
| VERIFIED | B325-virtio-rng-active-provider | virtio-rng active-provider teardown and hwrng promotion semantics. |
| SOURCE OK |  | virtio-vsock has explicit shutdown callback. |
| SOURCE OK |  | virtio-net has explicit shutdown callback. |
| SOURCE OK |  | virtio-snd has explicit shutdown callback. |
| SOURCE OK |  | 8250 serial has explicit shutdown callback. |
| SOURCE OK |  | PL011 serial has explicit shutdown callback. |
| SOURCE OK |  | i8042 keyboard has explicit shutdown callback. |
| SOURCE OK |  | Remove public `register_device` bypasses from driver model. |
| SOURCE OK |  | Remove public infallible `device_add` wrapper; production callers handle `try_device_add` errors. |
| SOURCE OK |  | Sysfs bus-driver controls are backed by model bind/unbind. |
| SOURCE OK |  | Sysfs exposes driver links. |
| SOURCE OK |  | Sysfs exposes `driver_override`. |
| VERIFIED |  | Sysfs exposes `modalias`. |
| SOURCE OK |  | Sysfs exposes aggregate PCI `resource`. |
| VERIFIED |  | Sysfs exposes indexed PCI `resourceN` BAR attributes. |
| SOURCE OK |  | Model-derived uevent environment includes current bound driver state. |
| VERIFIED |  | Model devices with `dev_t` expose `dev` attribute. |
| VERIFIED |  | Dynamic `/sys/dev/char` reverse index derives from model devices. |
| VERIFIED |  | Dynamic `/sys/dev/block` reverse index derives from model devices. |
| VERIFIED |  | Model-backed `mem` character devices publish Linux-style `/sys/class/mem` and virtual device directories. |
| VERIFIED |  | Model-backed `misc` character devices publish Linux-style `/sys/class/misc` and virtual device directories. |
| VERIFIED |  | Model-backed `sound` character devices publish Linux-style `/sys/class/sound` and virtual device directories. |
| VERIFIED |  | Model-backed `graphics` character devices publish Linux-style `/sys/class/graphics` and virtual device directories. |
| VERIFIED |  | `/sys/dev/char` resolves to real pseudo, misc, ALSA/OSS, fbdev, input, and DRM device objects. |
| VERIFIED |  | Model-backed virtual input, DRM, and character class devices expose `device` link when parent exists. |
| VERIFIED | B422-bind-unbind-uevent-stability | Bind/unbind change uevents are stable under parallel hosted tests and live netlink monitor: sysfs tests filter the shared uevent stream by event content and isolate unregister remove counters; `uevent_probe` now performs real `/sys/bus/virtio/drivers/virtio-snd/{unbind,bind}` while subscribed to `NETLINK_KOBJECT_UEVENT`, proving unbind emits `ACTION=change` without stale `DRIVER=virtio-snd` and rebind emits `ACTION=change` with `DRIVER=virtio-snd`. Evidence: `cargo test -p sysfs bind_unbind_emit_change_uevents_from_current_model_state -- --nocapture`, full parallel `cargo test -p sysfs -- --nocapture`, both musl probe compiles, x86_64 log `/tmp/b422-bind-unbind-uevent-stability-x86.log`, and aarch64 log `/tmp/b422-bind-unbind-uevent-stability-arm.log`. |
| VERIFIED | B422-bind-unbind-uevent-stability | Intermittent hosted sysfs uevent test isolation root cause fixed: parallel tests no longer assume their event is first in the global uevent broadcast queue, and the unregister-driver test no longer shares `BIND_REMOVES`; full parallel `cargo test -p sysfs -- --nocapture` passed 25/25. |
| VERIFIED | B424-bound-unbound-uevent-state-proof | Bound change uevents include `DRIVER=<name>`: current source requires `uevent_probe_bind_change` to match `ACTION=change`, `SUBSYSTEM=virtio`, `DEVPATH=/devices/virtio/<dev>`, and `DRIVER=virtio-snd`; hosted bind/unbind sysfs regression passes and both x86_64/aarch64 live logs contain `uevent_probe_bind_change: PASS`. |
| VERIFIED | B424-bound-unbound-uevent-state-proof | Unbound change uevents do not carry stale driver ownership: current source requires `uevent_probe_unbind_change` to match `ACTION=change`, `SUBSYSTEM=virtio`, and `DEVPATH=/devices/virtio/<dev>` while rejecting `DRIVER=virtio-snd`; hosted bind/unbind sysfs regression passes and both x86_64/aarch64 live logs contain `uevent_probe_unbind_change: PASS`. |
| VERIFIED |  | Block `uevent` attributes are writable and re-emit current model event. |
| VERIFIED |  | Input `uevent` attributes are writable and re-emit current model event. |
| VERIFIED |  | Model-backed virtual character class `uevent` attributes are writable. |
| VERIFIED |  | Root disk coldplug can re-emit block event from current state. |
| VERIFIED |  | Evdev coldplug can re-emit input event from current state. |
| VERIFIED |  | Sound coldplug can re-emit model-backed class event from current state. |
| SOURCE OK |  | Graphics/fbdev coldplug can re-emit model-backed class event from current state. |
| SOURCE OK |  | Misc and mem coldplug can re-emit model-backed class events from current state. |
| VERIFIED |  | Character-class remove/readd tests prove class symlink, parent link, and `/sys/dev/char` index disappear/reappear. |
| VERIFIED |  | Static procfs-era `/sys/class/misc/autofs` registration removed; autofs comes from model-owned misc device. |
| VERIFIED |  | Autofs exposes Linux `10:235` dev_t matching `/dev/autofs`. |
| VERIFIED |  | Built-in devfs pseudo-device publication has fallible `try_populate_defaults`. |
| VERIFIED |  | Built-in devfs pseudo-device population treats matching existing pseudo devices idempotently. |
| VERIFIED |  | Built-in devfs pseudo-device conflicts return driver-model error. |
| SOURCE OK |  | Console/tty boot node publication has fallible `try_register_devnodes` batch path. |
| SOURCE OK | TBD | Console/tty conflict rollback must be verified in source/tests for current main. |
| SOURCE OK |  | Boot-created serial/i8042 platform devices use explicit `try_device_add` handling. |
| SOURCE OK |  | Matching existing platform identities are reused. |
| SOURCE OK |  | Platform identity conflicts report fatal boot-boundary error. |
| SOURCE OK |  | PCI capability dumping is read-only for MSI-X. |
| SOURCE OK |  | MSI-X programming for virtio devices belongs to virtio-pci transport path. |
| VERIFIED |  | Virtio-pci accepts modern virtio PCI IDs only. |
| VERIFIED |  | Transitional virtio IDs are not mixed into modern cap-based path. |
| SOURCE OK |  | Virtio-pci creates child `virtio` devices through fallible model publication. |
| SOURCE OK |  | Child virtio drivers bind through the model. |
| SOURCE OK |  | Virtio child model-driver declarations are split into `pci-boot::virtio_child`. |
| SOURCE OK |  | PCI transport file no longer owns every child `drv::Driver` declaration. |
| SOURCE OK |  | Child probes do not import transport helper callbacks directly. |
| SOURCE OK |  | Virtio child binding uses one bus-facing `VirtioChildDriver` wrapper. |
| SOURCE OK |  | Virtio child wrapper centralizes matching by virtio device ID. |
| SOURCE OK |  | Virtio child wrapper centralizes child session begin. |
| SOURCE OK |  | Virtio child wrapper centralizes failed-probe transport release. |
| SOURCE OK |  | Virtio child wrapper centralizes successful transport publish. |
| SOURCE OK |  | Virtio child wrapper centralizes parent-key remove unpublish. |
| SOURCE OK |  | Virtio child wrapper centralizes shutdown key lookup. |
| SOURCE OK |  | Child drivers supply only profile, install, remove, and shutdown policy. |
| SOURCE OK |  | Virtio child device IDs for net/block/RNG/vsock/sound/input/GPU are supplied by child driver crates. |
| SOURCE OK |  | Virtio-gpu placeholder notify pointer marker removed. |
| VERIFIED |  | Shared `virtio` owns child bus/vendor matching through `VirtioChildDriverId`. |
| SOURCE OK |  | Child driver crates export their own descriptors. |
| SOURCE OK |  | PCI-backed child wrapper consumes child descriptors. |
| VERIFIED |  | Shared `virtio` owns transport-neutral child model-device identity. |
| VERIFIED |  | Shared `virtio` owns child bus name. |
| VERIFIED |  | Shared `virtio` owns synthetic `virtioN` address construction. |
| VERIFIED |  | Shared `virtio` owns modern PCI ID to virtio child ID conversion. |
| VERIFIED |  | Shared `virtio` owns virtio child class. |
| VERIFIED |  | Shared `virtio` owns parent-link matching. |
| VERIFIED |  | Shared `VirtioChildDeviceKey` wraps stable per-child runtime key. |
| NOT DONE | TBD | Current PCI-backed bus still derives child key from BDF; transport-neutral model needs non-PCI proof. |
| VERIFIED |  | `drv-virtio-rng` consumes `VirtioChildDeviceKey` for install/remove/shutdown/active promotion/probe seeding. |
| VERIFIED |  | `drv-virtio-input` consumes `VirtioChildDeviceKey` for install/remove/evdev lookup. |
| VERIFIED |  | `drv-virtio-vsock` consumes `VirtioChildDeviceKey` for install/remove/shutdown/context lookup/RX preposting. |
| NOT DONE | TBD | `drv-virtio-vsock` raw conversion remains at `net::vsock` owner-key boundary. |
| VERIFIED |  | `drv-virtio-blk` consumes `VirtioChildDeviceKey` for block init/registry/hot-remove/shutdown/tests. |
| VERIFIED |  | `drv-virtio-net` consumes `VirtioChildDeviceKey` for modern init/transport identity/netdev/TX/RX/neighbor/remove/shutdown/tests. |
| NOT DONE | TBD | `drv-virtio-snd` raw conversion remains at sound-core owner-key boundary. |
| VERIFIED |  | `drv-virtio-snd` consumes `VirtioChildDeviceKey` for install/context/hot-remove/shutdown/PCM scan/event teardown. |
| NOT DONE | TBD | `drv-virtio-gpu` still uses BDF as metadata and callback key in some DRM/fbdev private paths. |
| VERIFIED |  | `drv-virtio-gpu` consumes `VirtioChildDeviceKey` for device table/install/hot-remove/shutdown/probe-failure unwind/scanout teardown. |
| VERIFIED |  | Shared `virtio::run_child_probe` owns transport-neutral child probe lifecycle. |
| VERIFIED |  | Shared `virtio::VirtioProbeLease` owns one-shot transport-state lease. |
| VERIFIED |  | Hosted virtio tests cover idempotent probe lease ownership transfer. |
| VERIFIED |  | Shared `VirtioProbeOwnedFrames` owns frame ledger for prepared child probe. |
| VERIFIED |  | Failed child probes drain still-owned frames including net boot payload frames. |
| VERIFIED |  | Shared `run_child_remove` owns remove-before-unpublish sequencing. |
| VERIFIED |  | Shared `run_child_shutdown` owns typed-key shutdown dispatch. |
| NOT DONE | TBD | Shared `VirtioChildTransportSession` contract exists, but current implementation is still boot PCI-backed. |
| SOURCE OK |  | PCI-backed child session carries explicit `VirtioPciTransport` backend. |
| SOURCE OK |  | Raw virtio-pci probe/publish/unpublish helpers are private to transport module. |
| VERIFIED |  | Shared `VirtioChildResourceState` owns transport-neutral readiness/resource policy. |
| VERIFIED |  | Shared `VirtioChildProbeFacts` carries child-visible transport probe result. |
| SOURCE OK |  | `VirtioProbe` owns PCI/MMIO/MSI-X lifetime and opaque frame-release records. |
| SOURCE OK |  | Debug-only virtio probe trace fields live in `VirtioPciProbeTrace`. |
| SOURCE OK |  | Virtio-pci owns persistent transport MMIO mappings. |
| SOURCE OK |  | Virtio-pci owns MSI-X state. |
| SOURCE OK |  | Virtio-pci owns vring frame publication/teardown records for successful child probes. |
| SOURCE OK |  | Virtio-pci MSI-X state is owned optional/plural binding rather than zero-sentinel fields. |
| NOT DONE | TBD | MSI-X teardown masks table entries, disables MSI-X, and drops PCI memory decode in correct order under live remove/failure. |
| NOT DONE | TBD | `VirtioProbeState` exists; remaining transport ownership should move behind explicit state/boundary. |
| VERIFIED |  | Shared `VirtioResources` / `VirtQueueResource` handoff exists. |
| VERIFIED |  | Queue lookup validation centralized through `require_queue`. |
| VERIFIED |  | Child probes declare `VirtioChildRequirements`. |
| SOURCE OK |  | Generic mapped `DEVICE_CFG` window is carried to child drivers. |
| VERIFIED |  | Virtio extra queue setup uses transport queue plan rather than `needs_q1/q2/q3` booleans. |
| VERIFIED |  | Shared `virtio::queue_cfg` owns common-cfg queue programming protocol. |
| SOURCE OK |  | Virtio-pci supplies PMM/HHDM queue allocator adapter. |
| VERIFIED |  | Child profiles use shared `VirtioTransportProfile` and `VirtioQueuePlan`. |
| VERIFIED |  | Shared `common_cfg` owns reset/status/feature negotiation/FEATURES_OK/DRIVER_OK/queue-size scan. |
| VERIFIED |  | Shared common-cfg bring-up wrapper exists. |
| VERIFIED |  | Common queue-set helper owns allocator-driven frame ownership and partial-allocation unwind. |
| VERIFIED |  | Planned extra queue notify mappings are indexed by queue index. |
| SOURCE OK |  | Old q1-specific notify policy enum removed. |
| VERIFIED |  | Shared virtio owns indexed notify descriptors. |
| VERIFIED |  | Shared virtio owns child-visible `VirtQueueResource` assembly. |
| VERIFIED |  | Shared virtio owns final runtime handoff assembly through `VirtioRuntimeHandoff`. |
| VERIFIED |  | Shared `VirtioTransportProbeResult` owns completed-probe transport-neutral result. |
| SOURCE OK |  | Child drivers export transport profile declarations with feature masks, queue requirements, IRQ callback policy. |
| VERIFIED |  | Shared `ProgrammedQueues` exposes indexed queue lookup. |
| SOURCE OK |  | Virtio-pci debug probe trace carries indexed handoff records. |
| SOURCE OK |  | PCI-backed virtio child session owns failed-probe transport cleanup as idempotent session lifetime rule. |
| VERIFIED |  | Child readiness checks go through `VirtioChildRequirements` and `VirtioProbe::child_resources`. |
| VERIFIED |  | Virtio-snd requires all four queues before install. |
| VERIFIED |  | Virtio common-cfg FAILED helper exists. |
| VERIFIED |  | Virtio-pci marks FAILED on rejected FEATURES_OK or mandatory q0 programming failure. |
| VERIFIED |  | Failed virtio child probes release transport vring frames through recorded queue state. |
| SOURCE OK |  | Virtio-net late netdev registration failure unwinds transport failed-probe release after child runtime uninstall. |
| SOURCE OK |  | Virtio-blk reads capacity/block size in child driver from generic config resource. |
| VERIFIED |  | Virtio-net reads MAC in child driver from generic config resource. |
| VERIFIED |  | Virtio-gpu feature mask comes from GPU child driver. |
| SOURCE OK |  | Virtio-blk feature mask includes `VIRTIO_BLK_F_BLK_SIZE`. |
| SOURCE OK |  | Virtio-input/rng/vsock/snd feature masks come from child drivers. |
| SOURCE OK |  | Virtio-pci MSI-X setup names `NO_VECTOR`. |
| SOURCE OK |  | Virtio-pci records q0 queue vector in MSI-X binding. |
| NOT DONE | TBD | Virtio-pci clears MSI-X function mask when enabling table entry; needs live interrupt proof. |
| SOURCE OK |  | MSI-X binding helper validates requested table entry against decoded size. |
| SOURCE OK |  | Transport-owned MSI-X binding lifetime handles multiple entries. |
| SOURCE OK |  | Extra queue plans resolve IRQ callbacks into queue-indexed MSI-X entries. |
| SOURCE OK |  | Virtio-vsock reads guest CID in child driver from generic config resource. |
| SOURCE OK |  | Dead pci-boot vsock config pass-through removed. |
| NOT DONE | TBD | Virtio-vsock failed install owns reserved endpoint and bounce frames until installed transport takes ownership. |
| SOURCE OK |  | Virtio-snd reads jacks/streams/chmaps/controls in child driver from generic config resource. |
| SOURCE OK |  | Virtio-snd programs EVENTQ(1) with notify mapping and child-owned MSI-X callback. |
| SOURCE OK |  | Virtio-snd preposts writable event descriptors. |
| SOURCE OK |  | Virtio-snd drains EVENTQ from sound softirq. |
| SOURCE OK |  | Virtio-snd recycles used event descriptors. |
| SOURCE OK |  | Dead pci-boot sound config pass-through removed. |
| NOT DONE | TBD | Virtio-snd probe scratch/event/TX/RX frame ownership and teardown need fault-injection proof. |
| SOURCE OK |  | Virtio-input reads identity/capability from generic config resource. |
| VERIFIED |  | Virtio-input owns `/dev/input/eventN` publication/removal in child install/remove path. |
| SOURCE OK |  | Virtio-net no longer has PCI-transport-owned MAC config harvest. |
| SOURCE OK |  | Virtio-blk has per-device records. |
| SOURCE OK |  | Virtio-blk unregisters disks on remove. |
| NOT DONE | TBD | Virtio-blk freezes new I/O and waits for in-flight owner before reset; needs live and fault proof. |
| SOURCE OK |  | Virtio-blk dead config pass-through removed. |
| SOURCE OK |  | NVMe binds through model probe. |
| SOURCE OK |  | AHCI binds through model probe. |
| SOURCE OK |  | NVMe keeps typed per-BDF block-device state. |
| SOURCE OK |  | AHCI keeps typed per-BDF block-device state. |
| SOURCE OK |  | NVMe remove unregisters disks, quiesces hardware, returns queue/bounce frames. |
| SOURCE OK |  | AHCI remove unregisters disks, quiesces hardware, returns queue/bounce frames. |
| NOT DONE | TBD | NVMe/AHCI BAR mappings are dropped on probe failure/remove; needs leak/fault proof. |
| SOURCE OK |  | NVMe publication is per PCI function with `nvmeXn1` names. |
| SOURCE OK |  | AHCI publication is per PCI function with `sdX` names. |
| SOURCE OK | TBD | NVMe duplicate binds rejected before controller bring-up; needs hosted/live proof. |
| SOURCE OK | TBD | AHCI duplicate binds rejected before HBA bring-up; needs hosted/live proof. |
| SOURCE OK |  | AHCI publishes ATA IDENTIFY serial into block registry. |
| VERIFIED | B326-userspace-seat-driver-proof | Virtio-input supports multiple input device records. |
| VERIFIED |  | Virtio-input publishes `/dev/input/eventN` through model-owned devices. |
| VERIFIED |  | `/proc/bus/input/devices` derives from live input state. |
| VERIFIED | B327-virtio-input-queue-quiesce | Virtio-input clears event-queue bottom half when last queue removed. |
| VERIFIED | B327-virtio-input-queue-quiesce | Virtio-input shutdown uses explicit event-queue quiesce path. |
| VERIFIED | B327-virtio-input-queue-quiesce | Virtio-input hot-remove/shutdown address drain state by owning child key. |
| NOT DONE | TBD | Intermittent ARM no-progress watchdog: fast driver-path failed before `mouseprobe` then passed on rerun in B327, B337, B383, and B421; pre-push login smoke also timed out on attempt 1 then reached `oxide login:` on attempt 2. Failed logs `/tmp/b327-queue-quiesce-arm.log`, `/tmp/oxide-boot-smoke-arm-IdW5Zh.log`, `/tmp/b337-drm-render-nodes-withheld-arm.log`, `/tmp/oxide-boot-smoke-arm-jyMRB8.log`, `/tmp/oxide-boot-smoke-arm-vsmd0t.log`, `/tmp/b383-arm-driver-path.log`, `/tmp/oxide-boot-smoke-arm-WjMdLT.log`, `/tmp/b421-pci-identity-mismatch-arm-noprogress.log`; passing logs `/tmp/b327-queue-quiesce-arm-rerun.log`, `/tmp/b337-drm-render-nodes-withheld-arm-rerun.log`, `/tmp/b383-arm-driver-path-rerun.log`, `/tmp/oxide-boot-smoke-arm-nJVaKr.log`, `/tmp/oxide-boot-smoke-arm-laxjZl.log`, `/tmp/oxide-boot-smoke-arm-76xmcA.log`, `/tmp/b421-pci-identity-mismatch-arm.log`; B419 showed the old systemd path could wedge before `/bin/vsock_probe` started, so the driver proof moved to direct `/init` and passed; root-cause of the broader systemd no-progress remains separate. |
| VERIFIED | B328-virtio-input-drain-split | Virtio-input `drain.rs` split into focused keymap pipeline, queue lifetime, and ring-drain modules before more growth; `cargo test -p drv-virtio-input`, fast x86_64 driver path, and fast aarch64 driver path pass. |
| VERIFIED |  | `/proc/bus/input/devices` advertises `/devices/virtual/input/eventN`. |
| VERIFIED |  | Evdev `EVIOCGRAB` is per open file. |
| VERIFIED |  | Competing evdev grabs fail with `EBUSY`. |
| VERIFIED |  | Non-owner evdev clients do not drain/poll under another client's grab. |
| VERIFIED |  | Last close releases evdev grab. |
| VERIFIED |  | `EVIOCSCLOCKID` validates userspace clock id. |
| VERIFIED |  | `EVIOCREVOKE` marks current open file revoked and later reads fail with `ENODEV`. |
| VERIFIED |  | VFS has file-aware read/poll/release hooks for evdev semantics. |
| VERIFIED | B326-userspace-seat-driver-proof | Obsolete crate-level EVIOC recognizer removed. |
| VERIFIED |  | `EVIOCGREP`/`EVIOCSREP` implemented in real evdev file ioctl handler. |
| VERIFIED | B329-virtio-gpu-remove-child-key | Virtio-gpu remove is keyed to owning child key; removed BDF-keyed child-remove pre-unpublish and added hosted key-vs-BDF regression plus fast x86_64/aarch64 driver-path proof. |
| VERIFIED | B330-virtio-gpu-remove-teardown-order | Virtio-gpu remove tears down fbcon/fbdev/DRM/klog/tty scanout before backing release; source order is `uninstall(device_key)` before `uninstall_scanout(device_key)`, with hosted GPU tests and fast x86_64/aarch64 driver-path proof passing. |
| VERIFIED | B331-virtio-gpu-probe-failure-unwind | Virtio-gpu probe-failure unwind removes only failed child scanout; hosted post-init regression now runs, full GPU crate tests pass, and fast x86_64/aarch64 driver-path proof passes. |
| VERIFIED | B332-virtio-gpu-hot-remove-cleanup | Virtio-gpu hot-remove independently attempts console/fbdev, DRM, and scanout cleanup; hosted hot-remove regressions, full GPU crate tests, and fast x86_64/aarch64 driver-path proof pass. |
| VERIFIED | B333-virtio-gpu-device-state-key | Virtio-gpu installed device state is per child key; source audit, hosted key-vs-BDF tests, full GPU crate tests, and fast x86_64/aarch64 driver-path proof pass. |
| VERIFIED | B334-virtio-gpu-duplicate-key-reject | Virtio-gpu duplicate child-key install rejects `Error::Busy` before second DRM card/model publication; hosted duplicate-publication regression, full GPU crate tests, fast x86_64/aarch64 driver-path proof, and PR #2387 merge pass. |
| VERIFIED | B335-drm-card-id-stable-slots | DRM card IDs are stable slots: registry stores `Vec<Option<Arc<dyn DrmDriver>>>`, node inodes tag the stable card id, ioctl routing uses that tag, lower-slot reuse does not reroute an existing higher-slot fd, full DRM crate tests pass, fast x86_64/aarch64 driver-path proof passes, and PR #2388 merge pass. |
| VERIFIED | B336-drm-card-node-publication | DRM publishes `/dev/dri/cardN` per stable card slot; source audit, hosted metadata regression, full DRM crate tests, fast x86_64/aarch64 driver-path proof, line-cap check, and PR #2389 merge pass. |
| VERIFIED | B337-drm-render-nodes-withheld | DRM render nodes withheld until real render/GEM UAPI exists; source audit, hosted no-render publication regression, updated runtime `drm_probe` ENOENT check, full DRM crate tests, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, line-cap check, and PR #2390 merge pass. |
| VERIFIED | B338-drm-inode-tag-card-id | DRM inode tag encodes card id; source audit, hosted card/render inode-tag regression, full DRM crate tests, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, line-cap check, and PR #2391 merge pass. |
| VERIFIED | B339-drm-card-ioctl-slot-routing | DRM card ioctls route through matching backend slot; source audit, hosted stable-slot ioctl regression, full DRM crate tests, fast x86_64/aarch64 driver-path proof, line-cap check, and PR #2392 merge pass. |
| VERIFIED | B340-drm-sysfs-live-model-devices | `/sys/class/drm` and `/sys/devices/virtual/drm` derive from live DRM model devices; source audit, hosted sysfs DRM regressions, full sysfs crate tests, fast x86_64/aarch64 driver-path proof, line-cap check, and PR #2393 merge pass. |
| VERIFIED | B341-virtio-gpu-drm-real-parent | Virtio-gpu registers DRM card devices with real virtio child parent; source audit, hosted parent regression, full virtio-gpu crate tests, virtio child identity/session tests, pci-boot compile test, fast x86_64/aarch64 driver-path proof, line-cap check, and PR #2394 merge pass. |
| VERIFIED | B342-parented-drm-minors-links | Parented DRM minors live under owning device with class and `/sys/dev/char` links; source audit, focused hosted sysfs regressions, fast x86_64/aarch64 driver-path proof, line-cap check, and PR #2395 merge pass. |
| VERIFIED | B343-scanout-backing-bdf-keyed | Scanout backing runtime state is keyed by virtio child key instead of PCI BDF; source audit, hosted key-vs-BDF regression, full virtio-gpu and DRM tests, fast x86_64/aarch64 driver-path proof, line-cap check, and PR #2396 merge pass. |
| VERIFIED | B344-drm-setcrtc-pageflip-card-route | DRM SETCRTC/PAGE_FLIP hooks route by DRM card id to owning GPU; source audit, hosted card-id-to-driver-key regression, full DRM and virtio-gpu tests, fast x86_64/aarch64 driver-path proof, line-cap check, pre-push boot smoke, and PR #2397 merge pass. |
| VERIFIED | B345-drm-dumb-fb-card-owned | DRM dumb buffers and FB metadata are card-owned; source audit, hosted same-handle/same-FB-id card-isolation regression, full DRM tests, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, line-cap check, and PR #2398 merge pass. |
| VERIFIED | B346-drm-fb-scanout-resource-lifetime | Runtime scanout resources attach to DRM FB object and detach/unref on RMFB/unregister; source audit, hosted `clear_card_state` scanout-resource release regression, full DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2399 merge, and local main sync to `origin/main` at `6ffbc9b7` pass. |
| VERIFIED | B347-drm-unregister-drops-card-state | DRM unregister drops that card CRTC and dumb-buffer state; source audit, hosted per-card unregister teardown regression, full DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2400 merge, and local main sync to `origin/main` at `a62a9129` pass. |
| VERIFIED | B348-drm-master-open-file-state | DRM master state is per open file description; source audit, hosted dup/split-open/last-close master regression, full DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2401 merge, and local main sync to `origin/main` at `bdb8d725` pass. |
| VERIFIED | B349-drm-page-flip-file-events | DRM PAGE_FLIP events are per card open file and poll/read correctly; source audit, hosted duplicate-open/split-open/split-card poll-read regression, full DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2402 merge, and local main sync to `origin/main` at `3287909f` pass. |
| VERIFIED | B350-drm-magic-open-file-auth | DRM GET_MAGIC/AUTH_MAGIC allocate and authorize real per-open-file magic; forged `AUTH_MAGIC` now rejects unallocated magic, hosted magic-state/ioctl regressions, full DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2403 merge, and local main sync to `origin/main` at `8e78fe0d` pass. |
| VERIFIED | B351-drm-unique-version-uapi | DRM GET_UNIQUE and SET_VERSION marshal Linux UAPI structs; fixed GET_UNIQUE to stay empty until SET_VERSION, avoid partial undersized-buffer copies, and return driver version negotiation fields. Hosted regressions, full DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2404 merge, and local main sync to `origin/main` at `66d5c727` pass. |
| VERIFIED | B352-drm-atomic-empty-state | DRM MODE_ATOMIC empty-state gate now uses Linux 64-byte UAPI/ioctl, rejects reserved/event/async, keeps non-empty commits unsupported; hosted DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2405 merge, and local main sync to `origin/main` at `be5399d3` pass. |
| VERIFIED | B353-drm-client-cap-rejects-unsupported | DRM SET_CLIENT_CAP rejects unsupported atomic/writeback/aspect/stereo/cursor hotspot caps for enable and disable without mutating file state; hosted regression, full DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2406 merge, and local main sync to `origin/main` at `f910022a` pass. |
| VERIFIED | B354-drm-get-cap-supported-only | DRM GET_CAP clamps unsupported PRIME/syncobj/async/page-flip-target/modifiers/cursor caps to zero even when drivers over-report; hosted regression, full DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2407 merge, and local main sync to `origin/main` at `7eadc40e` pass. |
| VERIFIED | B355-drm-raw-writes-rejected | DRM card and private render-node raw writes return `EINVAL`; source audit, existing hosted regression, full DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, PR #2408 merge, and local main sync to `origin/main` at `21e0a9ba` pass. |
| VERIFIED | B356-drm-addfb2-modifier-reject | DRM ADDFB2 rejects modifier flag and nonzero modifier payloads while modifier support is absent; added focused hosted regression for nonzero modifier payload with flags clear; full DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2409 merge, and local main sync to `origin/main` at `8c2d61e3` pass. |
| VERIFIED | B357-drm-addfb-packed-rgb-validation | ADDFB/ADDFB2 validate packed-RGB metadata and bounds; added ADDFB2 unused-offset and legacy ADDFB backing-span regressions; full DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2410 merge, and local main sync to `origin/main` at `dc05b71a` pass. |
| VERIFIED | B358-fbdev-flush-blank-record | fbdev flush/blank ops are per `/dev/fbN` record; added hosted `/dev/fbN` FBIOBLANK/FBIO_WAITFORVSYNC regression proving selected inode routes to selected ops key; full fbdev tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2411 merge, and local main sync to `origin/main` at `4824dd77` pass. |
| VERIFIED | B359-virtio-gpu-fbdev-index-owner | Virtio-gpu scanout context records exact fbdev index and unpublishes by owner token; added owner-keyed fbdev-index store/take regression and serialized post_init global-state tests; full virtio-gpu tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2412 merge, and local main sync to `origin/main` at `91039d81` pass. |
| VERIFIED | B360-console-fbdev-transactional-publish | Console/fbdev publication now installs fbdev, ops, and stored idx before committing console owner token; lost owner commits unwind stored idx and fbdev record; hosted transactional regressions, full virtio-gpu tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2413 merge, and local main sync to `origin/main` at `e0c60058` pass. |
| VERIFIED | B361-shutdown-scanout-quiesce-in-place | Shutdown quiesces scanout in place without dropping publication/backing metadata; added hosted regression proving CTX, fbdev idx, framebuffer VA/size, allocation count, command-buffer PA, and fbdev record survive shutdown; full virtio-gpu tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2414 merge, and local main sync to `origin/main` at `380a7e00` pass. |
| VERIFIED | B362-fbcon-foreground-owner | VT foreground publication now uses one normal helper for fbcon renderer foreground and tty keyboard foreground; added hosted regression proving `ACTIVE_VT`, `tty::live::foreground()`, and `fbcon::kernel::foreground()` switch together; normal host check, full VT tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2415 merge, and local main sync to `origin/main` at `1b3a3d14` pass. |
| VERIFIED | B363-drm-dumb-mmap-pins-object | MODE_MAP_DUMB mmap uses `pin_mmap_backing`, VMA-owned `DrmDumbBacking`/`FileBacking`, shared-frame lookup, and Drop/unpin; existing table regression, full DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, PR #2416 merge, and local main sync to `origin/main` at `89ab2e44` pass. |
| VERIFIED | B364-drm-map-dumb-cookie-validation | MODE_MAP_DUMB cookies are high-tagged at bit 48 with handle bits 12..43; decoder rejects zero handle, low page-offset bits, and out-of-layout bits. Source audit, existing cookie regression, full DRM tests, line-cap check, fast x86_64/aarch64 driver-path proof, PR #2417 merge, and local main sync to `origin/main` at `a0cbb9bd` pass. |
| VERIFIED | B365-fbdev-fbio-usercopy-bounds | fbdev FBIO fixed-size args and cmap arrays use checked exclusive-end user range validation before read/write copies; added overflow regression, full fbdev tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2418 merge, and local main sync to `origin/main` at `70ac7dff` pass. |
| VERIFIED | B366-fbdev-getcmap-transp-efault | FBIOGETCMAP rejects invalid transparency pointer with `EFAULT`; added focused hosted regression, full fbdev tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2419 merge, and local main sync to `origin/main` at `50f507dc` pass. |
| VERIFIED | B367-virtio-gpu-probe-unwind-proof | Display-info probe command buffer and scanout framebuffer ownership/unwind have RAII transfer plus failed-probe cleanup proof; added focused hosted regression, full virtio-gpu tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2420 merge, and local main sync to `origin/main` at `c2e8e3cf` pass. |
| VERIFIED | B368-virtio-net-netdev-publish-owner | Virtio-net owns netdev publication/removal: `init_modern_with_rx_pool` publishes by child `DeviceKey`, `VirtioNetDev` carries the key, `REGISTERED_NETDEVS`/`NET_RUNTIMES` are key-owned, and `uninstall_modern` removes only the named key; added hosted netdev-runtime owner regression, full virtio-net tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2421 merge, and local main sync to `origin/main` at `11a52b12` pass. |
| VERIFIED | B369-virtio-net-rx-runtime-owner | Virtio-net owns RX runtime installation/removal: `install_rx_runtime` records iface/IP state by child `DeviceKey`, installs shared timers/softirq once, `remove_rx_runtime_for` removes only the named key and reports last-runtime state, and `uninstall_modern` releases shared RX resources only after the last runtime; extended hosted RX runtime regression, full virtio-net tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2422 merge, and local main sync to `origin/main` at `92bf93aa` pass. |
| VERIFIED | B370-virtio-net-no-boot-ipv4-policy | Virtio-net old boot-probe default IPv4 policy removed: `install_rx_runtime` seeds RX softirq state with `0.0.0.0`, later iface address updates flow through `set_softirq_ip_for_iface`, added hosted regression `rx_runtime_install_does_not_seed_boot_ipv4_policy`, full `drv-virtio-net` tests, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2423 merge, and local main sync to `origin/main` at `c9a786f6` pass. |
| VERIFIED | B371-virtio-net-install-remove-keyed | Virtio-net install/remove keyed to owning child key: PCI child dispatch passes `session.device_key()` into `init_modern_with_rx_pool`, remove/shutdown pass the parent `VirtioChildDeviceKey`, `ModernNetState` stores that key, install rejects duplicate keys, and `uninstall_modern` removes only the matching key. Focused install/remove regressions, full `drv-virtio-net` tests, fast x86_64/aarch64 driver-path proof, PR #2424 merge, and local main sync to `origin/main` at `fb70eeb3` pass. |
| VERIFIED | B372-virtio-net-keyed-cursors | Virtio-net TX/RX cursors live in keyed device records: `ModernNetState` owns `tx_last_used`, `tx_next_avail`, `rx_last_used`, and `rx_next_avail`; `tx_frame_for` and `rx_poll_for` first select the matching `device_key`; RX pool install initializes per-device `rx_next_avail`. Focused RX-pool cursor regression, full `drv-virtio-net` tests, fast x86_64/aarch64 driver-path proof, PR #2425 merge, and local main sync to `origin/main` at `ebf774cb` pass. |
| VERIFIED | B373-virtio-net-netdev-owning-key | Published `NetDev` carries owning key: `VirtioNetDev` stores `device_key`, constructs runtime state with the same key, and uses the key for TX/neighbor paths. Added hosted owner-key assertions, full `drv-virtio-net` tests, line-cap check, fast x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2426 merge, and local main sync to `origin/main` at `b03912d3` pass. |
| VERIFIED | B374-virtio-net-iface-rx-keyed-tables | Registered iface ownership and RX softirq runtime are keyed tables: `REGISTERED_NETDEVS` stores `(DeviceKey, NetIfaceId)`, `set_registered_iface`/`registered_iface_for`/`remove_registered_iface` select by key, `RX_RUNTIMES` stores `device_key`, and RX install/update/remove paths preserve per-key state. Focused iface/RX regressions, full `drv-virtio-net` tests, fast x86_64/aarch64 driver-path proof, PR #2427 merge, and local main sync to `origin/main` at `df4907d0` pass. |
| VERIFIED | B375-virtio-net-ethn-visible-names | Visible netdev names are child-runtime owned: `allocate_net_name` returns first free `ethN`, `ensure_net_runtime` stores it per child key, and `VirtioNetDev::name()` exposes it; focused `net_runtime_names_are_unique_and_reusable`, full virtio-net tests, line-cap check, x86_64/aarch64 driver-path proof, PR #2428 merge, and local main sync to `origin/main` at `66cf1bff` pass. |
| VERIFIED | B376-virtio-net-rx-stats-per-netdev | RX stats are per netdev/runtime: `NetRuntime` owns RX counters by child key, `rx_poll_for` increments the runtime selected by `device_key`, and `VirtioNetDev::stats()` exposes those counters; extended focused regression, full virtio-net tests, line-cap check, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2429 merge, and local main sync to `origin/main` at `b3643ee6` pass. |
| VERIFIED | B377-virtio-net-ipv4-arp-runtime-owned | IPv4 ARP cache entries are runtime-owned: `NetRuntime` embeds `ArpCache`, RX ARP/IP learning inserts through `net_runtime_for(device_key)`, TX lookup reads that keyed runtime, and ARP GC walks runtime caches; focused `arp_cache_is_keyed_by_device`, full virtio-net tests, line-cap check, x86_64/aarch64 driver-path proof, PR #2430 merge, and local main sync to `origin/main` at `a81c39de` pass. |
| VERIFIED | B378-virtio-net-hot-remove-key-cleanup | Hot-remove clears netdev/interface/RX runtime by child key: PCI child remove calls `uninstall_modern(device_key)`, uninstall unregisters/removes iface and net runtime by key, removes only the matching RX runtime, and releases shared RX state only after the last runtime; focused uninstall/RX regressions, full virtio-net tests, line-cap check, x86_64/aarch64 driver-path proof, PR #2431 merge, and local main sync to `origin/main` at `3445c15a` pass. |
| VERIFIED | B379-virtio-net-shared-rx-last-runtime | Shared NetRx bottom half and ARP-GC timer stay installed until last RX runtime removed: `install_rx_runtime` arms both shared resources, `remove_rx_runtime_for` reports whether removal emptied the keyed runtime table, and `release_rx_shared_runtime_if_last` tears down softirq/timer only when the table is empty; tightened regression proves timer and softirq survive first removal and clear after final removal, with full virtio-net tests, x86_64/aarch64 driver-path proof, PR #2432 merge, and local main sync to `origin/main` at `2178cd35` passing. |
| VERIFIED | B380-virtio-net-ipv6-ndp-stack-owned | IPv6 NDP learning goes through the stack-owned interface table: virtio-net RX delivers IPv6 frames to `NetStack::deliver_rx_ipv6(iface, ...)`, stale driver-private `learn_ndp_from_ipv6` path/test removed, stack NDP tests prove `(iface, IPv6)` scoped NS/NA learning, full virtio-net tests, line-cap check, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2433 merge, and local main sync to `origin/main` at `0fbf754b` pass. |
| VERIFIED | B381-virtio-net-ipv6-tx-stack-ndp | Virtio-net TX resolves IPv6 neighbors through registered interface stack NDP table: kernel `ndp_lookup_for_device` maps `DeviceKey` to `registered_iface_for(device_key)` and calls `net::sock::stack().ndp_lookup(iface, next_hop)`, `VirtioNetDev::xmit` uses that resolver before `tx_frame_for`, hosted stack NDP tests, virtio-net tests, line-cap check, x86_64/aarch64 driver-path proof, PR #2434 merge, and local main sync to `origin/main` at `cdd8d243` pass. |
| VERIFIED | B382-virtio-net-multidev-rebind-proof | Fast-init live proof passes on x86_64 and aarch64 for two virtio-net devices, `eth0`/`eth1`, sysfs driver `unbind`/`bind`, restored virtio-net driver readdir state, and normal input tail; ARM PID1 selection now honors `/init`, rootfs cache keys multidev mode; normal x86_64/aarch64 smoke, PR #2435 merge, and local main sync to `origin/main` at `d09f5123` pass. |
| VERIFIED | B383-core-ipv6-ndp-iface-cache | Core IPv6 stack NDP cache is keyed by `(iface, IPv6 address)` and unregister purges the removed iface's entries; source audit, hosted NDP tests, line-cap check, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2436 merge, and local main sync to `origin/main` at `505521d8` pass. |
| VERIFIED | B384-virtio-vsock-remove-keyed | Virtio-vsock remove is keyed to the owning child device: source audit proves probe/remove/shutdown pass `VirtioChildDeviceKey`, driver ctx/endpoint/TX/RX select by owner key, hosted regression proves `uninstall(key1)` leaves `key2` ctx/endpoint live, fast x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2437 merge, and local main sync to `origin/main` at `2efc98f8` pass. |
| VERIFIED | B385-virtio-vsock-rx-bh-installed | Virtio-vsock clears `VsockRx` bottom half only for installed transport: source audit proves `SOFTIRQ_INSTALLED` gates handler install/clear and removal clears only after last ctx, hosted regression proves unpublished ctx teardown leaves live endpoint/RX bottom half installed, fast x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2438 merge, and local main sync to `origin/main` at `4db141ad` pass. |
| VERIFIED | B386-net-vsock-owner-keyed-endpoints | Upper `net::vsock` endpoint records are owner-keyed: source audit proves `ENDPOINTS` stores `{ owner, guest_cid, tx }` and install/reserve/publish/quiesce/uninstall/CID/TX/RX paths select by owner; hosted TX routing regression, full vsock tests, fast x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2439 merge, and local main sync to `origin/main` at `947cb224` pass. |
| VERIFIED | B387-af-vsock-bind-specific-local-cid | AF_VSOCK bind honors specific local CID: source audit proves `sys_bind` resolves `sockaddr_vm` cid through `net::vsock::bind_owner_for_cid`, ANY maps to owner 0, live specific CID maps to owning endpoint, dead/quiesced CID returns `EADDRNOTAVAIL`; hosted bind-owner regression, full vsock tests, `syscalls` check, fast x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2440 merge, and local main sync to `origin/main` at `72aebeca` pass. |
| VERIFIED | B388-vsock-listener-backlogs-owner-port | Listener backlogs are keyed by `(owner, port)`: source audit proves `Listener { owner, local_port, backlog }`, `add_listener` rejects duplicates only for the same pair, inbound requests queue through exact owner before wildcard, and `pop_accept` reads only the matching owner/port backlog; hosted same-port dual-owner regression, full vsock tests, fast x86_64/aarch64 driver-path smokes, pre-push boot smoke, PR #2441 merge, and local main sync to `origin/main` at `a7a5312f` pass. |
| VERIFIED | B389-vsock-close-releases-state | AF_VSOCK close releases listener/backlog/connection state: source audit proves `Drop for VsockSocket` removes listeners via `TABLE.remove_listener(owner, port)` and closes connected sockets via `vsock::close`; `remove_listener` drains pending backlog keys, closes those conns, removes table records, and deletes the listener; focused drop cleanup tests, full vsock tests, fast x86_64/aarch64 driver-path smokes, PR #2442 merge, and local main sync to `origin/main` at `e3f505da` pass. |
| VERIFIED | B390-virtio-rng-child-key-records | Virtio-rng keeps per-child-key records: source audit proves `RngState` stores `VirtioChildDeviceKey`, registry records are per-device handles, install/uninstall/shutdown/find and `fill_from_device` select exact keys, active provider uses `active_key`, and pci-boot passes `session.device_key()`; hosted child-key regression, full drv-virtio-rng tests, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2443 merge, and local main sync to `origin/main` at `68940f57` pass. |
| VERIFIED | B391-virtio-rng-seeds-bound-device | Virtio-rng seeds from just-bound device: source audit proves `install(device_key, resources)` seeds via `fill_from_device(device_key, &mut seed)` after registering that child, while active hwrng reads still use `fill()`/`active_handle()`; hosted requested-child fill regression, full drv-virtio-rng tests, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2444 merge, and local main sync to `origin/main` at `75c9cfe8` pass. |
| VERIFIED | B392-virtio-rng-active-provider | Virtio-rng active `/dev/hwrng` provider promotion/removal: source audit proves `uninstall` removes by exact key, promotes only live records through `promote_active_locked`, clears hwrng when no live provider remains, and publish failure clears matching `active_key`; hosted active-provider regressions, full drv-virtio-rng tests, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2445 merge, and local main sync to `origin/main` at `197482f2` pass. |
| VERIFIED | B393-virtio-snd-install-remove-keyed | Virtio-snd install/remove keyed to owning child key: source audit proves pci-boot passes `session.device_key()`, `SndInstall` stores `device_key`, `CTX` records are keyed, duplicate install rejects exact key, `uninstall` clears sound card/ops by `sound_owner(device_key)` and removes context by exact key; hosted keyed-removal regression, full drv-virtio-snd tests, x86_64/aarch64 driver-path proof, pre-push boot smoke, PR #2446 merge, and local main sync to `origin/main` at `6f09ae22` pass. |
| VERIFIED | B394-sound-card-owner-keyed-numbers | Sound card layer allocates owner-keyed ALSA card numbers: `SoundCard` stores `owner` and `card`, `reserve_card(owner)` is idempotent per owner and allocates first free card for new owners, `card_number(owner)` selects by owner, and `unregister_card(owner)` removes only that owner; focused owner/card regression, full sound tests, x86_64/aarch64 driver-path proof, PR #2447 merge, and local main sync to `origin/main` at `db69465f` pass. |
| VERIFIED | B395-sound-card-per-card-node-publication | Sound card layer publishes per-card ALSA/OSS nodes: `publish_card_nodes(owner, card, ...)` emits `snd/controlC<N>`, direction-gated `snd/pcmC<N>D0[p|c]`, card-scaled OSS nodes, and card-0 legacy aliases; `register_card(owner)` stores published node handles and `unregister_card(owner)` deletes only those handles; focused per-card node regression, full sound tests, x86_64/aarch64 driver-path proof, PR #2448 merge, and local main sync to `origin/main` at `a76db156` pass. |
| VERIFIED | B396-sound-ops-route-by-owner | Sound ops route by owner: node dispatch carries `SndData.owner`, `ops_for(owner)` selects exact owner with live card reservation, PCM/capture/control/OSS paths pass the explicit owner through state lookup and backend callbacks, and focused owner-routing regression, full sound tests, x86_64/aarch64 driver-path proof, PR #2449 merge, and local main sync to `origin/main` at `cac90846` pass. |
| NOT DONE | TBD | Direct ALSA PCM `PCM_INFO` on PCM nodes must report the node card number instead of hard-coded/default card metadata. |
| NOT DONE | TBD | Hosted `sound` tests share global card state and can fail under default parallel execution; serial `--test-threads=1` passes. |
| VERIFIED | B397-sound-unregister-rejects-non-owners | Sound unregister rejects non-owners: `unregister_card(owner)` first requires an exact owner record before deleting stored node handles or clearing control/OSS/capture/PCM/ops state; focused non-owner unregister test, serial full sound tests, x86_64/aarch64 driver-path proof, PR #2450 merge, and local main sync to `origin/main` at `e5fe3f55` pass. |
| VERIFIED | B398-virtio-snd-eventq-owner-accounting | Virtio-snd raw EVENTQ accounting is keyed by transport owner: EVENTQ rings, buffer PA, last-used, avail idx, and raw/drained counters live in `Ctx` records selected by `device_key`; focused drain regression proves only the advanced context records/requeues events, full drv-virtio-snd tests, x86_64/aarch64 driver-path proof, PR #2451 merge, and local main sync to `origin/main` at `a6506b42` pass. |
| VERIFIED | B399-virtio-snd-multicard-rebind-proof | Virtio-snd multi-card live proof added: env-gated second QEMU sound device, rootfs probe, and `smoke-virtio-snd-multidev`; C probe compile, `cargo check -p xtask`, full `drv-virtio-snd` tests, serial full `sound` tests, and x86_64/aarch64 smoke logs pass; PR #2452 merge and local main sync to `origin/main` at `36d0b388` pass. |
| VERIFIED | B400-virtio-msix-child-owned-handlers | Source audit shows `VirtioChildOps::profile()` supplies MSI-X handlers and PCI transport consumes profile fields without virtio-ID dispatch; added hosted profile-handler regression, `cargo test -p virtio`, `cargo test -p pci-boot`, x86_64 driver-path log `/tmp/b400-x86-driver-path.log`, and aarch64 driver-path log `/tmp/b400-arm-driver-path.log` all pass. |
| VERIFIED | B401-virtio-pci-probe-exit-unwind | Virtio-pci probe now carries `VirtioProbeLease` inside `VirtioProbe`: failed/unpublished drop paths release frames/MSI-X, clear PCI MEM/BUS_MASTER, and unmap transport mappings once; publish consumes the lease and transfers mappings/MSI-X/vring frames. Source audit, `cargo test -p virtio`, `cargo test -p pci-boot`, x86_64 driver-path log `/tmp/b401-x86-driver-path.log`, and aarch64 driver-path log `/tmp/b401-arm-driver-path.log` all pass. |
| VERIFIED | B402-sound-card-publication-model-owned | Sound card publication now tracks explicit owner publication state (`reserved`/`publishing`/`published`) so duplicate publication is guarded before devnode creation; duplicate register proof now asserts no rollback removals; `cargo test -p sound -- --nocapture --test-threads=1`, `cargo test -p drv-virtio-snd -- --nocapture`, x86_64 driver-path log `/tmp/b402-x86-driver-path.log`, and aarch64 driver-path log `/tmp/b402-arm-driver-path.log` all pass. |
| VERIFIED | B403-fbdev-publication-unwind-on-model-failure | Fbdev registration now routes hosted tests through model publication, and the model-conflict regression proves `register()` returns `INVALID_FB_INDEX` with no stale framebuffer record when `drv::try_device_add` rejects `fb0`; `cargo test -p fbdev -- --nocapture --test-threads=1`, x86_64 driver-path log `/tmp/b403-x86-driver-path.log`, and aarch64 driver-path log `/tmp/b403-arm-driver-path.log` all pass. |
| VERIFIED | B404-8250-receive-irq-owned | 8250 runtime RX is IRQ4-owned: removed the serial-core poll fallback and 8250 `rx_poll` export, corrected timer-driven UART comments, and `cargo test -p drv-uart-16550 -p drv-serial -p serialtty -- --nocapture --test-threads=1` passes; x86_64 `/tmp/b404-x86-driver-path.log` and aarch64 `/tmp/b404-arm-driver-path.log` runtime proof pass. |
| VERIFIED | B405-pl011-receive-irq-owned | PL011 runtime RX is SPI-33-owned: removed the PL011 `rx_poll` export and stale timer-poll comment, and `cargo test -p drv-uart-pl011 -p drv-serial -p serialtty -- --nocapture --test-threads=1` passes; x86_64 `/tmp/b405-x86-driver-path.log` and aarch64 `/tmp/b405-arm-driver-path.log` runtime proof pass. |
| VERIFIED | B406-i8042-receive-irq-owned | i8042 runtime RX is IRQ1-owned: source audit proves `probe()` installs IRQ1 handler/vector/I/O-APIC redirection before enabling the controller IRQ bit, corrected stale poll wording, and `cargo test -p drv-ps2-keyboard -p drv-virtio-input -p tty -p console -- --nocapture --test-threads=1` passes; x86_64 `/tmp/b406-x86-driver-path.log` and aarch64 `/tmp/b406-arm-driver-path.log` runtime proof pass. |
| VERIFIED | B407-serial-input-remove-rebind-state | Source audit shows 8250 remove clears RX enable, masks/free vector, resets IRQ pin/vector and BASE/PRESENT; PL011 remove disables RX/INTID, frees handler, clears BASE/PRESENT; i8042 bringdown disables scan/controller IRQ, masks/free vector, resets IRQ pin/vector and PRESENT. `cargo test -p drv-uart-16550 -p drv-uart-pl011 -p drv-serial -p drv-ps2-keyboard -p drv-virtio-input -p serialtty -p tty -p console -- --nocapture --test-threads=1`, x86_64 `/tmp/b407-x86-driver-path.log`, and aarch64 `/tmp/b407-arm-driver-path.log` pass. |
| VERIFIED | B408-timer-registry-owned-ids | Timer registry returns opaque non-zero `TimerId`s from `register_periodic` and unregisters by exact owned ID; virtio-net stores its ARP GC timer ID and unregisters on remove. Added hosted timer ownership regressions. `cargo test -p timer -p drv-virtio-net -p net -p sched -- --nocapture --test-threads=1`, x86_64 `/tmp/b408-x86-driver-path.log`, and aarch64 `/tmp/b408-arm-driver-path.log` pass. |
| VERIFIED | B409-driver-model-setup-policy | Driver core is authoritative for Device/Driver add, bind, unbind, remove, shutdown, sysfs, and devtmpfs ordering; PCI publication uses `drv::try_device_add`, and virtio parent/child bring-up is owned by model `Driver::probe` wrappers. Remaining transport/core cleanup is tracked by the following virtio-specific rows. `cargo test -p drv -p pci-boot -p virtio -- --nocapture --test-threads=1`, x86_64 `/tmp/b409-x86-driver-path.log`, and aarch64 `/tmp/b409-arm-driver-path.log` pass. |
| VERIFIED | B410-virtio-transport-policy-boundary | Current source has shared virtio policy at the child/core boundary: child drivers export `VirtioTransportProfile`s; shared `virtio` owns child requirements, queue plans, early payload policy, resource readiness, runtime handoff, and probe/remove/shutdown lifecycle helpers; `pci-boot` supplies the concrete PCI session and MMIO/MSI lifetime. `cargo test -p virtio -p pci-boot -p drv-virtio-net -p drv-virtio-blk -p drv-virtio-rng -p drv-virtio-vsock -p drv-virtio-snd -p drv-virtio-input -p drv-virtio-gpu -- --nocapture --test-threads=1`, x86_64 `/tmp/b410-x86-driver-path.log`, and aarch64 `/tmp/b410-arm-driver-path.log` pass. |
| VERIFIED | B411-virtio-irq-core-bus-split | Child drivers declare IRQ callbacks through shared `VirtioTransportProfile`; `pci-boot` only consumes those profiles to bind/program/release MSI-X and register the supplied handler. Shared profile tests prove callback placement, hosted `cargo test -p virtio -p pci-boot -p drv-virtio-net -p drv-virtio-vsock -p drv-virtio-input -p drv-virtio-snd -- --nocapture --test-threads=1` passes, and x86_64 `/tmp/b411-x86-driver-path.log` plus aarch64 `/tmp/b411-arm-driver-path.log` pass. Remaining full virtio bus/core extraction stays in later row. |
| VERIFIED | B412-probe-failure-devres-proof | Added `VirtioProbeDevres` as the single virtio-pci probe resource owner for cfg reset, frame release, MSI-X release, PCI command disable, mapping unmap, and successful publish transfer. Added child-probe fault-point lifecycle coverage proving failures release once and never publish. `cargo test -p virtio -p pci-boot -p drv-virtio-net -p drv-virtio-blk -p drv-virtio-rng -p drv-virtio-vsock -p drv-virtio-snd -p drv-virtio-input -p drv-virtio-gpu -- --nocapture --test-threads=1`, x86_64 `/tmp/b412-x86-driver-path.log`, and aarch64 `/tmp/b412-arm-driver-path.log` pass. |
| VERIFIED | B413-devtmpfs-model-owned-publication | Source audit proves hardware-backed nodes publish through `drv::try_device_add`: block, evdev, fbdev, DRM, hwrng, sound, console, and boot pseudo devices; direct `devfs::register*` users are fixed dirs, ptys, coredumps, or other non-hardware namespace entries. `cargo test -p drv -p devfs -p block -p drv-virtio-input -p fbdev -p drm -p drv-virtio-rng -p sound -p console -- --nocapture --test-threads=1`, x86_64 `/tmp/b413-x86-driver-path.log`, and aarch64 `/tmp/b413-arm-driver-path.log` pass. |
| VERIFIED | B414-driver-devnode-readd-loops | Existing hosted remove/readd loops cover block, evdev, fbdev, DRM, and hwrng; B414 adds same-owner sound card unregister/register restore coverage. Console tty nodes are boot-owned fixed nodes, not hot-remove loop devices; x86_64/aarch64 driver-path proof covers their boot publication path. `cargo test -p drv -p devfs -p block -p drv-virtio-input -p fbdev -p drm -p drv-virtio-rng -p sound -p console -- --nocapture --test-threads=1`, x86_64 `/tmp/b414-x86-driver-path.log`, and aarch64 `/tmp/b414-arm-driver-path.log` pass. |
| NOT DONE | B415-bind-unbind-readd-proof | Aggregate repeated bind/unbind/remove/readd proof remains unverified: `driver_anal.md` requires QEMU hotplug/rebind proof for PCI, virtio, block, net, DRM/fbdev, input, sound, RNG, UART, and PS/2; existing driver-core and hosted devnode loops are useful but explicitly not a substitute. Complete the following concrete live-proof rows, then revisit this aggregate row. |
| VERIFIED | B416-nvme-ahci-multicontroller-proof | NVMe/AHCI per-BDF source audit, opt-in two-controller QEMU harness, `/bin/storage_multictrl_probe`, hosted `drv/sysfs/block`, x86_64 `/tmp/b416-x86-storage-multictrl-3.log`, and aarch64 `/tmp/b416-arm-storage-multictrl.log` pass. |
| VERIFIED | B417-virtio-net-live-multidev-proof | Existing virtio-net multidev probe and QEMU two-device mode satisfy the row: source audit confirms keyed install/remove/rebind path; hosted `drv-virtio-net/net/virtio/pci-boot`, x86_64 `/tmp/b417-x86-virtio-net-multidev.log`, and aarch64 `/tmp/b417-arm-virtio-net-multidev.log` pass. |
| VERIFIED | B418-virtio-gpu-live-multigpu-proof | Added opt-in two-GPU QEMU mode and `/bin/virtio_gpu_multidev_probe`; source audit plus hosted `drv-virtio-gpu/drm/fbdev/virtio/pci-boot` tests pass. x86_64 `/tmp/b418-x86-virtio-gpu-multidev.log` and aarch64 `/tmp/b418-arm-virtio-gpu-multidev.log` prove two DRM cards, sysfs unbind/rebind, keyed `hot_remove`, and input/sound/block/net tail. |
| VERIFIED | B419-virtio-vsock-live-multiendpoint-proof | Virtio-vsock primary compatibility route works with multiple live endpoints: direct `/init` proof installs cid=3/cid=4 and completes host round-trip on x86_64 `/tmp/b419-x86-vsock-multiendpoint-fastinit.log` and aarch64 `/tmp/b419-arm-vsock-multiendpoint-fastinit-3.log`; hosted `net`, `drv-virtio-vsock`, and `pci-boot` tests pass. |
| VERIFIED | B420-virtio-snd-event-control-proof | Virtio-snd live multi-card proof now covers control/event UAPI shape without fabricated mixer controls: `controlC0`/`controlC1` prove card info, PCM discovery/info for playback+capture, empty control element list, missing element `ENOENT`, and event subscription before and after live rebind. Direct musl builds pass for x86_64/aarch64; hosted `cargo test -p sound -p drv-virtio-snd -- --nocapture --test-threads=1` passes; fast live logs `/tmp/b420-x86-virtio-snd-event-control.log` and `/tmp/b420-arm-virtio-snd-event-control.log` pass. |
| NOT DONE | TBD | UART and PS/2 model drivers remain intentional singleton hardware paths, not general multi-device serial/input infrastructure. |
| NOT DONE | TBD | QEMU-visible runtime bind/unbind/rebind certification incomplete. |
| NOT DONE | TBD | PCI lifecycle remains shallow: bus 0/simple QEMU path, no full bridge/resource/runtime semantics. |
| SOURCE OK |  | Production model drivers in current source have explicit shutdown callbacks; default shutdown remains test-only. |
| NOT DONE | TBD | Extract remaining real virtio bus/core split from `pci-boot`. |
| NOT DONE | TBD | Add explicit fault-injection coverage after every allocation, mapping, registration, IRQ/MSI step, queue setup, and userspace publication. |
| NOT DONE | TBD | Prove repeated bind/unbind/remove/readd loops under QEMU for PCI. |
| NOT DONE | TBD | Prove repeated bind/unbind/remove/readd loops under QEMU for virtio parent/child. |
| NOT DONE | TBD | Prove repeated bind/unbind/remove/readd loops under QEMU for block. |
| NOT DONE | TBD | Prove repeated bind/unbind/remove/readd loops under QEMU for net. |
| NOT DONE | TBD | Prove repeated bind/unbind/remove/readd loops under QEMU for DRM/fbdev. |
| NOT DONE | TBD | Prove repeated bind/unbind/remove/readd loops under QEMU for input. |
| NOT DONE | TBD | Prove repeated bind/unbind/remove/readd loops under QEMU for sound. |
| NOT DONE | TBD | Prove repeated bind/unbind/remove/readd loops under QEMU for RNG. |
| NOT DONE | TBD | Prove repeated bind/unbind/remove/readd loops under QEMU for UART. |
| NOT DONE | TBD | Prove repeated bind/unbind/remove/readd loops under QEMU for PS/2. |
| NOT DONE | TBD | Finish Linux-visible sysfs/devtmpfs/class contracts across every class; B418 found `/dev/dri/card1` remains openable after virtio-gpu model hot-remove even though `hot_remove` reports device/scanout removed. |
| NOT DONE | TBD | `/sys/dev/{char,block}` exists and resolves; needs live udev proof. |
| NOT DONE | TBD | `/sys/bus/<bus>/drivers/<driver>` bind/unbind/device-link shape exists; needs live proof. |
| NOT DONE | TBD | Driver-directory device symlinks resolve to canonical `/sys/devices/...`; needs live proof. |
| NOT DONE | TBD | Generalize PCI command enable/disable, BAR mapping ownership, MSI/MSI-X setup/teardown, `enable`, bridge topology, and runtime semantics. |
| NOT DONE | TBD | Audit all remaining direct subsystem side effects so hardware-backed nodes/classes register in owning probe and remove in owning remove. |
| NOT DONE | TBD | Add concrete per-driver shutdown coverage where hardware quiesce differs from hot-unplug remove and prove reboot/poweroff path. |
| NOT DONE |  | Old claim: live hardware bring-up mostly bypasses true driver model. Current source has model `probe` for PCI/NVMe/AHCI/virtio/platform paths. |
| NOT DONE |  | Old claim: `pci-boot` directly calls `virtio_probe_arch`, `nvme_probe`, `ahci_probe`. Current source publishes PCI model devices and registered model drivers probe. |
| NOT DONE |  | Old claim: `Driver::probe` is mostly no-op for live model drivers. Current main has substantive probe methods for main hardware drivers. |
| NOT DONE |  | Old claim: synthetic virtio devices are registered but runtime binding still direct PCI boot. Current source binds child drivers on `virtio` bus through wrapper. |
| NOT DONE | TBD | Keep `driver_progress.md` updated after each row is fixed/proven. |
| NOT DONE | TBD | For every branch: implement one coherent item, run relevant hosted tests, push, PR, merge, return to fresh `main`, and continue with no drift. |
