# Driver plan

Date: 2026-07-04

ACTIVE NOW: `B366-fbdev-getcmap-transp-efault` — IN AUDIT.

Current active item: `>>> ACTIVE >>> B366-fbdev-getcmap-transp-efault`.

Current B366 gate: add focused FBIOGETCMAP transparency-pointer regression, run fbdev tests, x86_64/aarch64 driver-path proof, push PR, merge, then sync local `main`.

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
| SOURCE OK |  | Remove old flat `DriverEntry` / `probe_all(bdf)` live driver path. |
| SOURCE OK |  | Make `drv::Device`, `drv::Driver`, `try_device_add`, `device_del`, `bind`, `bind_addr`, and `unbind` authoritative in `crates/drivers/drv/src/model.rs`. |
| SOURCE OK |  | Remove public `drv::auto_bind`; keep automatic attachment internal to `try_device_add` and `register_driver`. |
| SOURCE OK |  | Route explicit binds through sysfs driver `bind` control path. |
| SOURCE OK |  | PCI enumeration creates `pci` model devices with BAR resources through fallible model publication. |
| SOURCE OK |  | Register NVMe, AHCI, and virtio-pci as model drivers. |
| SOURCE OK |  | Attach PCI drivers through driver core rather than enumeration-local direct bind calls. |
| SOURCE OK |  | PCI model-device publication is fallible and idempotent for repeated enumeration of matching `(pci, addr)` identity. |
| NOT DONE | TBD | PCI identity mismatch handling must not rebound as the same function; needs live/multi-bus proof. |
| SOURCE OK |  | Model binding rejects already-bound devices. |
| SOURCE OK |  | Model binding verifies bus/driver matching. |
| SOURCE OK |  | Model binding calls `Driver::probe`. |
| SOURCE OK |  | Model binding records binding only after successful probe. |
| SOURCE OK |  | Probe failure leaves device unbound and retriable. |
| SOURCE OK |  | Driver registration attaches newly registered driver to existing unbound matching devices. |
| SOURCE OK |  | Driver unregistration detaches devices bound to that driver before removing the driver from registry. |
| SOURCE OK |  | New model device attaches to already registered matching drivers after devtmpfs/sysfs publication setup and before add uevent. |
| SOURCE OK |  | Initial auto-probe does not emit a separate bind-change event before add uevent. |
| SOURCE OK |  | Add uevent can carry current `DRIVER=<name>` state. |
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
| NOT DONE | TBD | Bind/unbind change uevents must be stable under parallel tests and live udev monitor; current source passes serial hosted tests, parallel hosted run exposed shared listener/test isolation issue. |
| NOT DONE | TBD | Intermittent hosted sysfs uevent test isolation: full `cargo test -p sysfs` failed in B342 on `device_del_emits_remove_uevent_before_model_disappears` missing `ACTION=remove`, then the test passed alone; a later full run failed `bind_unbind_emit_change_uevents_from_current_model_state` missing `DEVPATH=/devices/platform/sysfs-bind-uevent0`. Root-cause separately. |
| SOURCE OK |  | Bound change uevents include `DRIVER=<name>`. |
| SOURCE OK |  | Unbound change uevents do not carry stale driver ownership. |
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
| NOT DONE | TBD | Intermittent ARM no-progress watchdog: fast driver-path failed before `mouseprobe` then passed on rerun in B327 and B337; pre-push login smoke also timed out on attempt 1 then reached `oxide login:` on attempt 2. Failed logs `/tmp/b327-queue-quiesce-arm.log`, `/tmp/oxide-boot-smoke-arm-IdW5Zh.log`, `/tmp/b337-drm-render-nodes-withheld-arm.log`, `/tmp/oxide-boot-smoke-arm-jyMRB8.log`, `/tmp/oxide-boot-smoke-arm-vsmd0t.log`; passing logs `/tmp/b327-queue-quiesce-arm-rerun.log`, `/tmp/b337-drm-render-nodes-withheld-arm-rerun.log`, `/tmp/oxide-boot-smoke-arm-nJVaKr.log`, `/tmp/oxide-boot-smoke-arm-laxjZl.log`; root-cause separately. |
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
| >>> ACTIVE >>> IN AUDIT | B366-fbdev-getcmap-transp-efault | FBIOGETCMAP rejects invalid transparency pointer with `EFAULT`; source has conditional `cm.transp` user-range validation before transparency writes, focused regression and arch proof pending. |
| NOT DONE | TBD | Display-info probe command buffer and scanout framebuffer ownership/unwind need fault proof. |
| NOT DONE |  | Virtio-net owns netdev publication/removal. |
| NOT DONE |  | Virtio-net owns RX runtime installation/removal. |
| NOT DONE |  | Virtio-net old boot-probe default IPv4 policy removed. |
| NOT DONE |  | Virtio-net install/remove keyed to owning child key. |
| NOT DONE |  | Virtio-net TX/RX cursors live in keyed device records. |
| NOT DONE |  | Published `NetDev` carries owning key. |
| NOT DONE |  | Registered iface ownership and RX softirq runtime are keyed tables. |
| NOT DONE |  | Netdev visible names allocated as `ethN`. |
| NOT DONE |  | RX stats are per netdev. |
| NOT DONE |  | IPv4 ARP cache entries owned by virtio-net runtime. |
| NOT DONE |  | Hot-remove clears netdev/interface/RX runtime by child key. |
| NOT DONE |  | Shared NetRx bottom half and ARP-GC timer stay installed until last RX runtime removed. |
| NOT DONE |  | IPv6 NDP learning goes through stack-owned interface table. |
| NOT DONE |  | Virtio-net TX resolves IPv6 neighbors through registered interface stack NDP table. |
| NOT DONE | TBD | Virtio-net multi-device bind/unbind/rebind needs live QEMU proof. |
| NOT DONE |  | Core IPv6 stack NDP cache keyed by `(iface, IPv6 address)`. |
| NOT DONE |  | Virtio-vsock remove keyed to owning child key. |
| NOT DONE |  | Virtio-vsock clears `VsockRx` bottom half only for installed transport. |
| NOT DONE |  | Upper `net::vsock` stores owner-keyed endpoint records. |
| NOT DONE |  | AF_VSOCK bind honors specific local CID by resolving live endpoint. |
| NOT DONE |  | Listener backlogs keyed by `(owner, port)`. |
| NOT DONE |  | AF_VSOCK close releases listener/backlog/connection state. |
| NOT DONE |  | Virtio-rng keeps per-child-key records. |
| NOT DONE |  | Virtio-rng seeds from just-bound device. |
| NOT DONE | B325-virtio-rng-active-provider | Virtio-rng active `/dev/hwrng` provider promotion/removal must pass hosted tests and not leave stale active key. |
| NOT DONE |  | Virtio-snd install/remove keyed to owning child key. |
| NOT DONE |  | Sound card layer allocates owner-keyed ALSA card numbers. |
| NOT DONE |  | Sound card layer publishes per-card ALSA/OSS nodes. |
| NOT DONE |  | Sound ops route by owner. |
| NOT DONE |  | Sound unregister rejects non-owners. |
| NOT DONE |  | Virtio-snd raw EVENTQ accounting keyed by transport owner. |
| NOT DONE | TBD | Virtio-snd multi-card bind/unbind/rebind needs live QEMU proof. |
| NOT DONE |  | Virtio MSI-X handler ownership is child-declared, not transport PCI-ID special-case dispatch. |
| NOT DONE |  | Virtio-pci clears PCI MEM/BUS_MASTER and drops mappings on early transport probe exits after enable. |
| NOT DONE |  | Sound card publication is model-owned and duplicate publication guarded. |
| NOT DONE |  | Fbdev publication unwinds framebuffer record on model publication failure. |
| NOT DONE |  | 8250 receive path is IRQ-owned rather than timer-poll fallback. |
| NOT DONE |  | PL011 receive path is IRQ-owned rather than timer-poll fallback. |
| NOT DONE |  | i8042 receive path is IRQ-owned. |
| NOT DONE |  | 8250/PL011/i8042 remove paths clear driver state for later rebind. |
| NOT DONE |  | Timer registry returns owned timer IDs and supports explicit unregister. |
| NOT DONE | TBD | Driver model authoritative at Device/Driver level, but some setup policy remains in bus/transport helper code. |
| NOT DONE | TBD | Virtio common transport and child policy still too concentrated in `pci-boot` transport/session boundary. |
| NOT DONE | TBD | Virtio IRQ callback ownership improved, but true virtio-core/bus split remains incomplete. |
| NOT DONE | TBD | Probe failure unwind improved but lacks general devres stack and step-by-step fault injection proof. |
| NOT DONE | TBD | Devtmpfs publication model-owned for hardware-backed nodes; direct devfs users must stay limited to fixed pseudo/non-hardware namespace cases. |
| NOT DONE | TBD | Driver-owned devnode remove/readd hosted loops cover block, evdev, fbdev, DRM, hwrng; broaden to all subsystem nodes. |
| NOT DONE | TBD | Repeated bind/unbind/remove/readd behavior not proven across all subsystems. |
| NOT DONE | TBD | NVMe/AHCI multi-controller QEMU bind/unbind/rebind proof missing. |
| NOT DONE | TBD | Virtio-net live multi-device proof missing. |
| NOT DONE | TBD | Virtio-gpu live multi-card/multi-GPU proof missing. |
| NOT DONE | TBD | Virtio-vsock primary compatibility route with multiple live endpoints needs live proof. |
| NOT DONE | TBD | Virtio-snd live multi-card proof and broader event/control coverage missing. |
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
| NOT DONE | TBD | Finish Linux-visible sysfs/devtmpfs/class contracts across every class. |
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
