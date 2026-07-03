# Driver and driver-system correctness analysis

Date: 2026-07-03

## Position

The current driver system is not yet a Linux-correct driver model.

It has useful pieces:

- per-driver crates under `crates/drivers`
- a `drv::Device` registry
- a `drv::Driver` trait
- sysfs/devtmpfs hooks
- PCI enumeration
- virtio-pci transport bring-up
- block, net, DRM, input, sound, RNG, NVMe, AHCI, UART, and PS/2 driver code

But the actual architecture is split between two worlds:

1. An older flat `DriverEntry` / `probe_all(bdf)` path in `crates/drivers/drv/src/lib.rs`.
2. A newer `Device` / `Driver` / `device_add` model in `crates/drivers/drv/src/model.rs`.

The real hardware bring-up mostly bypasses both as a true driver model. PCI enumeration in `crates/kernel/pci-boot` directly enables devices, maps BARs, configures virtqueues, installs global runtime state, and only then registers/binds model drivers as a sysfs-visible afterthought.

That must be corrected. The driver model should own matching, probing, binding, error unwind, remove, shutdown, sysfs state, devtmpfs publication, and uevents. The boot PCI path should enumerate devices and hand them to the driver core, not contain the drivers.

## Progress ledger

Current status after the July 3, 2026 driver-fixes branch work:

- Overall: about 70% through cleanup/stabilization, about 42% through the full Linux-grade architecture conversion. The remaining gap is not small polish; the model still needs to become the causal owner of full transport probe/remove instead of `pci-boot`.
- Done: virtio-net now owns installation/removal of its `NetRx` softirq handler instead of leaving a driver-owned bottom half installed from `pci-boot`.
- Done: first pure virtio transport helpers moved into `crates/drivers/virtio`: modern device-id decoding, notify PA calculation, queue-resource construction, and common/queue requirement checks.
- Done: driver model now has a probe-driven bind path (`bind_driver`/`auto_bind`) that rejects duplicate bind, leaves failed probes unbound and retriable, and calls bound-driver `remove` during `device_del`.
- Done: virtio-rng now has explicit `uninstall`, common-cfg reset, and bounce-frame release; devfs has a clearable `/dev/hwrng` source hook, and the rng model driver clears the hook before hardware teardown.
- Done: virtio-snd install now treats failed mandatory `PCM_INFO` as probe failure, unwinds the singleton, resets the device, and frees driver-owned frames instead of publishing a partial card. The `sound` crate has a node unregister primitive; sound node removal still needs to be wired into a real sound-device remove path.
- Done: virtio-blk has a duplicate-BDF publication guard so the same PCI function cannot publish multiple `vd*` disks on re-entry.
- Done: virtio-blk disk publication is now model-probe causal. `pci-boot` still performs generic virtio-pci transport setup, but it stages a typed `BlkInit`; `VirtioBlkDrv::probe` consumes it, calls the block engine, and only then `bind_driver` records the bound driver.
- Done: virtio-blk now has a model remove path that unregisters the block disk, removes the devtmpfs/model block node through `block::registry::unregister`, clears the BDF publication guard, and releases the driver-owned contiguous bounce region through a matching PMM `free_contig`.
- Still open: `pci-boot` still performs most virtio transport bring-up directly. The next major work is moving transport ownership and error-unwind for virtio-blk, then repeating the pattern for net/input/gpu/rng/snd/vsock.

## Current architecture

### Driver core

`crates/drivers/drv/src/lib.rs` still exposes the legacy probe system:

- `DriverEntry`
- `register(DriverEntry)`
- `probe_all(bdf)`

This path is mostly obsolete. It is a flat list of probe functions and has no real device object, no binding state, no sysfs lifecycle, no remove, no devtmpfs connection, and no useful bus semantics.

`crates/drivers/drv/src/model.rs` is the newer model:

- `Device`
- `Driver`
- `register_device`
- `register_driver`
- `bind`
- `bind_addr`
- `device_add`
- `device_del`
- sysfs hooks
- devtmpfs hooks

This is the right direction, but it is currently additive rather than authoritative.

### PCI and virtio bring-up

`crates/kernel/pci-boot/src/lib.rs` enumerates PCI bus 0, enables Memory and BusMaster, logs BARs/caps, registers a PCI `drv::Device`, optionally registers a synthetic virtio `drv::Device`, and then calls direct probe functions:

- `virtio_probe_arch(d)`
- `nvme_probe(d)`
- `ahci_probe(d)`

`crates/kernel/pci-boot/src/virtio_drv.rs` directly performs modern virtio-pci transport bring-up. It configures features, MSI-X, queues, notify windows, runtime ring addresses, and then calls driver-specific install functions. At success sites it calls `model_bind(...)`, which registers a no-op `drv::Driver` and stamps the already-initialized device as bound.

That means driver binding is currently descriptive, not causal. The device is already live before the model says it is bound.

### Device publication

`device_add()` currently does:

1. `register_device()`
2. sysfs hook fires
3. sysfs hook emits add uevent
4. devtmpfs hook creates `/dev` node

This order is wrong for Linux-visible behavior. Userspace can process an add uevent before the matching `/dev` node exists.

Also, many real devices still use `register_device()` instead of `device_add()`, so they enter the model without devtmpfs linkage.

### Runtime state

Several drivers use singleton global state:

- virtio-gpu: single `DEV: Option<VirtioGpuDev>`
- virtio-net modern: single `MODERN_DEV`
- virtio-rng: single `CTX`
- virtio-vsock: single `CTX`
- virtio-snd: single `CTX`
- UART drivers: global `PRESENT` and base state
- PS/2 keyboard: global present/poll state

Some subsystems are per-device already or closer to it:

- block registry stores multiple disks
- DRM core can register multiple DRM drivers/cards in principle
- fbdev has a registry
- input has pieces of per-device support, but `/dev/input/event0` and procfs metadata still include synthetic/singleton paths

Singleton runtime state is acceptable only for explicitly singleton hardware or transitional boot code. It is not acceptable as the general driver model.

## Things we are doing wrong

### 1. The driver model is not the source of truth

The model records devices and bound driver names, but most real probe work happens elsewhere.

Wrong:

- PCI boot code brings a device up directly.
- The driver later registers a no-op model driver.
- `bind()` stamps a string into the device.
- sysfs looks like a driver bound, but the model did not actually bind it.

Correct:

- PCI enumeration creates a `Device`.
- Driver core matches registered drivers.
- Driver core calls `driver.probe(&Device)`.
- Probe allocates resources and publishes child devices only after success.
- Driver core records binding only after probe returns success.

### 2. There are two competing driver APIs

The legacy `DriverEntry/probe_all` path and the newer `Device/Driver` path overlap.

This creates ambiguity:

- Which API owns probing?
- Which API owns matching?
- Which API owns failure?
- Which API owns remove?
- Which API owns sysfs?

The old flat API should be deprecated and removed once all live drivers use the real model.

### 3. `probe()` is mostly a no-op

The `Driver` trait has `probe`, `remove`, and `shutdown`, but live model drivers often use default no-op `probe()` because the real work already happened in `pci-boot`.

This defeats the point of a driver model.

Every real hardware driver should move bring-up into `probe()` or into a bus-specific probe method called by `probe()`.

### 4. Binding has no error contract

`bind()` is currently effectively:

- set `dev.driver = Some(driver_name)`
- fire bind hook

It does not:

- check whether the device is already bound
- validate the driver exists
- validate the driver matches
- call `probe`
- handle probe failure
- return Linux-like errors
- unwind partial state

This is not Linux-correct. Duplicate bind should fail. Binding to a non-matching driver should fail. Probe failure should leave the device unbound and clean.

### 5. There is no real unbind/remove path

`Driver::remove()` exists, but the model does not properly use it.

Missing:

- `/sys/bus/<bus>/drivers/<driver>/unbind`
- model-level `unbind`
- remove uevents
- driver symlink removal
- driver directory backref removal
- interrupt teardown
- DMA/free-page teardown
- BAR unmap
- devfs node removal
- sysfs child cleanup
- net/block/input/sound/DRM child unregister

Hot-unplug and bind/unbind tests cannot be correct until this exists.

### 6. Probe has no partial-failure unwind discipline

Real probes allocate many resources:

- PCI command bits
- BAR mappings
- MSI/MSI-X vectors
- IRQ handlers
- DMA pages
- virtqueues
- block disk registrations
- netdev registrations
- DRM nodes
- input nodes
- sound nodes
- devtmpfs nodes
- sysfs nodes

If a later step fails, earlier steps must be unwound in reverse order.

Today, much of bring-up is linear boot code. That makes success paths easier but leaves failure paths under-specified.

### 7. PCI bus handling is too shallow

PCI enumeration currently focuses on bus 0 and immediate device bring-up.

Missing or incomplete:

- multi-bus enumeration
- bridge handling
- PCI resource ownership
- BAR sizing/assignment where firmware did not do it
- MSI/MSI-X lifecycle as a device-owned resource
- `enable` sysfs behavior
- `driver_override`
- `modalias`
- `resource*`
- proper PCI device parent/child topology
- bind/unbind interface

The current approach is enough for simple QEMU, not enough for Linux-correct driver infrastructure.

### 8. Virtio transport is not factored as a bus/core

Virtio-pci setup lives in `pci-boot` and directly knows too much about individual virtio device types.

Correct shape:

- PCI driver binds virtio-pci functions.
- virtio-pci transport creates virtio bus devices.
- virtio core negotiates features and owns common virtqueue setup.
- virtio child drivers bind by virtio device ID.
- virtio-blk, virtio-net, virtio-gpu, virtio-input, virtio-rng, virtio-vsock, and virtio-snd probe through the virtio bus.

Today the synthetic `virtio` devices are registered, but actual runtime binding still happens through direct PCI boot code.

### 9. Per-device state is inconsistent

Block is moving toward per-device state. Several other drivers are still singleton.

This blocks:

- multiple virtio-net devices
- multiple virtio-blk disks in a clean model
- multiple GPUs
- multiple input devices
- multiple sound cards
- hot-unplug
- rebinding
- fault injection tests

Every driver must either:

- support multiple devices with per-device state, or
- explicitly reject the second device before publishing anything userspace-visible.

Silent overwrite of singleton state is wrong.

### 10. Sysfs is too synthetic and incomplete

Sysfs currently synthesizes some bus views from the registry. That is fine as an implementation technique, but the observable Linux contract is incomplete.

Missing or weak:

- `/sys/bus/<bus>/drivers/<driver>/bind`
- `/sys/bus/<bus>/drivers/<driver>/unbind`
- driver directory device symlinks
- device `driver` symlink correctness
- device `subsystem` symlink
- `modalias`
- PCI resources
- remove/change event behavior
- per-class child relationships

The issue is not that sysfs is synthesized. The issue is that the synthesized model does not yet expose Linux's required state transitions and links.

### 11. Device nodes are not all model-owned

Some nodes are created through `device_add`, some through direct `devfs::register`, and some through subsystem-specific registration. This makes it hard to guarantee:

- correct `rdev`
- correct `/sys/dev/char`
- correct `/sys/dev/block`
- correct uevents
- correct teardown

The long-term rule should be: a device node belongs to a registered device object or a registered class device object. Direct `devfs::register` should be limited to fixed pseudo-devices and early boot exceptions.

### 12. Driver ownership boundaries are blurred

`pci-boot` depends on and calls into many drivers directly. Drivers depend on boot-probe-provided addresses and global hooks. This is understandable for bootstrap, but it should not remain the architecture.

Correct direction:

- bus code enumerates
- transport core maps and abstracts
- driver probe owns device-specific setup
- subsystem core owns class registration
- driver core owns lifecycle

## What should stay in the kernel

These are kernel responsibilities:

- bus enumeration
- driver matching and binding
- device probing
- resource allocation and ownership
- DMA and MMIO mapping
- IRQ/MSI/MSI-X setup
- devtmpfs node creation
- sysfs device/class/bus topology
- kobject uevents
- block/net/input/sound/DRM kernel APIs
- remove/shutdown/quiesce

## What should not be in the kernel

These should not be driver-core policy:

- udev rules
- persistent naming policy such as `/dev/disk/by-*` beyond kernel-provided identity attributes
- permissions policy
- seat tagging policy
- hwdb-derived properties
- desktop/session policy
- userspace service activation policy

The kernel should expose Linux-compatible facts. Userspace should make policy decisions.

## Correction plan

### Phase 1: make one driver model authoritative

Declare the `Device` / `Driver` model authoritative.

Actions:

- mark `DriverEntry` / `probe_all` legacy
- stop adding new users of `DriverEntry`
- add a real `driver_core::bind_device` path that calls `probe`
- make `bind` return `Result`
- check already-bound state
- check driver exists
- check driver matches unless using explicit override
- bind only after successful probe
- add model-level `unbind`

Acceptance:

- duplicate bind returns a Linux-compatible error
- bind to non-matching driver fails
- failed probe leaves the device unbound
- sysfs state reflects bound/unbound truth

### Phase 2: fix lifecycle ordering

Correct `device_add` and `device_del`.

Add path:

1. allocate/register internal device
2. create sysfs-visible object
3. create devtmpfs node if any
4. emit `add`

Remove path:

1. quiesce users
2. emit `remove` at the Linux-correct point
3. remove child class devices
4. remove devtmpfs nodes
5. remove sysfs visibility
6. release resources

Acceptance:

- `udevadm monitor` sees add/change/remove
- `/dev` node exists by the time add is processed
- remove deletes `/dev` and `/sys` views

### Phase 3: move PCI probing into drivers

PCI enumeration should only enumerate and register PCI devices.

Then:

- PCI bus core matches PCI drivers by id/class
- `nvme` probes through `NvmeDriver::probe`
- `ahci` probes through `AhciDriver::probe`
- `virtio-pci` probes as a PCI driver

Acceptance:

- `pci-boot` no longer calls `nvme_probe`, `ahci_probe`, or direct virtio device install functions
- all successful probes correspond to real model bindings
- probe failures are visible as unbound devices in sysfs

### Phase 4: introduce a real virtio bus/core

Split virtio into:

- `virtio-pci` transport driver
- virtio core
- virtio bus devices
- virtio child drivers

Flow:

1. PCI finds virtio-pci function.
2. virtio-pci driver maps caps and creates virtio device.
3. virtio core negotiates common features and exposes virtqueue allocation helpers.
4. virtio child driver probes by virtio device ID.

Acceptance:

- `/sys/bus/pci/devices/...` shows the virtio-pci function
- `/sys/bus/virtio/devices/virtioN` shows the virtio device
- virtio child driver binds under `/sys/bus/virtio/drivers/...`
- PCI parent/virtio child links resolve

### Phase 5: add managed resources

Add devres-like cleanup or an explicit per-probe resource stack.

Resources to manage:

- BAR mappings
- MMIO windows
- DMA pages
- IRQ vectors
- MSI/MSI-X table entries
- virtqueues
- softirq handlers
- timers
- block disks
- netdevs
- DRM minors
- input event nodes
- sound devices
- devtmpfs nodes
- sysfs class devices

Acceptance:

- fault injection after each probe step leaks nothing
- bind/unbind loop of 100 cycles leaks no IRQs, DMA pages, VA mappings, sysfs nodes, or devfs nodes

### Phase 6: remove singleton assumptions

For every driver:

- convert runtime state to per-device state, or
- reject second device before publishing anything

Priority:

1. virtio-net
2. virtio-gpu
3. virtio-input
4. virtio-snd
5. virtio-rng
6. virtio-vsock
7. UARTs

Acceptance:

- two-device QEMU tests either expose both devices correctly or expose exactly one and leave the other unbound with a clear reason

### Phase 7: complete sysfs driver interfaces

Implement:

- `/sys/bus/<bus>/drivers/<driver>/bind`
- `/sys/bus/<bus>/drivers/<driver>/unbind`
- driver directory device symlinks
- device `driver` symlink
- device `subsystem` symlink
- `driver_override`
- `modalias`
- remove/change uevents

Acceptance:

- manual bind/unbind works for at least virtio-blk
- duplicate bind fails
- unbind removes children and devnodes
- rebind restores them

### Phase 8: subsystem registration cleanup

Each subsystem should provide a central registration API:

- block: gendisk-like disk and partition registration
- net: netdev registration
- DRM: card/render/connector registration
- input: input device and event handler registration
- sound: ALSA card/device/control registration
- tty: tty driver and tty device registration
- fbdev: framebuffer registration

Device drivers should call subsystem registration from probe and unregister from remove.

Acceptance:

- `/proc/devices`
- `/proc/bus/input/devices`
- `/proc/diskstats`
- `/sys/class/*`
- `/sys/dev/{char,block}`

all derive from real registries, not duplicated hard-coded publication paths.

## Immediate next tasks

1. Make `drv::bind` a real fallible operation that calls `Driver::probe`.
2. Add `drv::unbind` and call `Driver::remove`.
3. Fix `device_add` ordering so devtmpfs exists before add uevent.
4. Add remove uevents to `device_del`.
5. Pick one driver as the first migration target. Best candidate: virtio-blk, because it has clear visible acceptance through `/dev/vda`, `/sys/block/vda`, mount, and `lsblk`.
6. After virtio-blk, migrate virtio-net or virtio-input. virtio-net tests netdev/rtnetlink; virtio-input tests class devices and graphical login dependencies.

## Do not do this

Do not keep adding sysfs illusions that claim a driver is bound if the model did not actually probe and bind it.

Do not fix multi-device bugs by silently ignoring second devices after partially initializing them.

Do not add userspace policy to the kernel to paper over missing driver/sysfs/uevent behavior.

Do not expand `pci-boot` into a larger pile of direct driver calls. It should shrink over time.

Do not publish `/dev` or `/sys` nodes before the owning driver/subsystem can service them.
