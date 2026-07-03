# Driver and driver-system status ledger

Date: 2026-07-03

Scope: this ledger describes only the dirty worktree at
`/home/nd/oxide/kernel-driver-fixes` on branch `codex/driver-fixes`.
There is a separate worktree at `/home/nd/oxide/kernel` on `main`; do not read
this document as a statement about `main` or any other branch until these
changes are committed and merged.

## Current position

This branch has moved the kernel substantially away from the old boot-probe
shape, but it is not a Linux-complete driver model yet.

Estimated branch-local status:

- Driver-core lifecycle cleanup: about 75% complete.
- Concrete driver probe/remove cleanup: about 65% complete.
- Device publication through model-owned sysfs/devtmpfs/class state: about 65%
  complete.
- Full Linux-grade driver architecture, including proper bus factoring,
  hotplug, fault injection, and multi-device coverage: about 40% complete.

The percentages are engineering estimates for this branch only. They are not
test-pass claims.

## Complete or substantially complete on this branch

- The old flat `DriverEntry` / `probe_all(bdf)` implementation path is gone
  from the live driver path.
- `drv::Device`, `drv::Driver`, `device_add`, `device_del`, `bind`,
  `auto_bind`, and `unbind` are the authoritative model path in
  `crates/drivers/drv/src/model.rs`.
- PCI enumeration creates `pci` model devices with BAR resources and calls
  `drv::auto_bind`; NVMe, AHCI, and virtio-pci are registered as model drivers.
- Model binding rejects already-bound devices, verifies bus/driver matching,
  calls `Driver::probe`, records the binding only after success, and leaves the
  device unbound when probe fails.
- Model unbind calls `Driver::remove` before clearing the binding.
- `device_del` unbinds first, emits remove while the object is still visible,
  removes devtmpfs state, and then drops the device from the registry.
- Public `register_device` bypasses have been removed from the driver model;
  `device_add` is the intended publication entry.
- Sysfs bus-driver controls are backed by the model path for bind/unbind, with
  driver links, `driver_override`, `modalias`, PCI `resource`, and model-derived
  uevent environment coverage improved on this branch. Model devices with
  `dev_t` now expose a `dev` attribute and dynamic `/sys/dev/char` and
  `/sys/dev/block` reverse indexes.
- PCI capability dumping is read-only again for MSI-X; MSI-X programming for
  virtio devices belongs to the virtio-pci transport probe/remove path.
- The virtio-pci transport accepts modern virtio PCI IDs only. Transitional
  IDs are not mixed into the modern cap-based path.
- Virtio-pci creates child `virtio` devices through `device_add` and child
  virtio drivers bind through the model.
- Virtio-pci owns persistent transport MMIO mappings, MSI-X state, and vring
  frame publication/teardown records for successful child probes.
- The shared virtio resource handoff exists through `VirtioResources` and
  `VirtQueueResource`, with queue lookup validation centralized through
  `require_queue`. Child probes now build those resources through one
  transport-owned helper path instead of rebuilding queue handoff state in each
  child glue path.
- Virtio-blk has per-device records, unregisters disks on remove, freezes new
  I/O, waits for its single in-flight request owner, resets the device, and
  returns child-owned bounce allocation when safe.
- NVMe and AHCI now bind through model probes and keep typed block-device state;
  remove unregisters disks, quiesces hardware state, and returns queue/bounce
  frames. Their BAR mappings are owned and dropped on probe failure/remove.
- Virtio-input supports multiple input device records, publishes
  `/dev/input/eventN` through model-owned devices, generates
  `/proc/bus/input/devices` from live input state, and clears its event-queue
  bottom half when the last queue is removed.
- Virtio-gpu remove is keyed to the owning parent BDF and tears down
  fbcon/fbdev/DRM/klog/tty scanout state before backing memory is released.
  Probe-failure unwind only removes scanout state for the failed probe's BDF.
- Virtio-net owns netdev publication/removal and RX runtime
  installation/removal: iface/IP bottom-half state, ARP-GC timer, and `NetRx`
  handler are installed from the net driver path and removed after reset. The
  old boot-probe default IPv4 policy is gone; the RX path learns IPv4 state
  from normal address configuration hooks. Virtio-net install/remove is now
  keyed to the owning parent BDF, so a remove for another device cannot clear
  the installed transport. TX/RX queue cursors now live in the installed
  device state, and the TX primitive has a BDF-keyed entry point.
- Virtio-vsock remove is keyed to the owning parent BDF and clears its
  `VsockRx` bottom half only for the installed transport. The upper
  `net::vsock` layer is still a single global guest-CID/TX-hook protocol
  endpoint, so simultaneous multi-transport vsock is not complete, but it now
  rejects a second active hook instead of overwriting the live endpoint.
- Virtio-rng now keeps per-BDF records, seeds from the just-bound device,
  removes by owning parent BDF, and promotes `/dev/hwrng` publication to a
  remaining RNG device on active-provider removal. Virtio-snd install/remove
  is now keyed to the owning parent BDF and releases child-owned queue/buffer
  resources only for the matching transport; the sound card layer remains a
  single global card.
- Virtio MSI-X handler ownership is no longer selected by a transport-side
  PCI-ID special-case dispatch. Child virtio driver probes now pass the
  optional queue-0 IRQ callback into the virtio-pci setup path; the PCI
  transport still owns MSI-X table/vector programming and teardown.
- Sound card publication is model-owned and registration is now guarded so a
  repeated probe cannot publish duplicate ALSA/OSS nodes.
- Fbdev publication now unwinds its live framebuffer record when model-owned
  `/dev/fbN` publication fails, preventing partial framebuffer state from
  outliving its devtmpfs node.
- 8250, PL011, and i8042 keyboard receive paths are owned by driver IRQ setup
  instead of timer-poll fallback paths, and their remove paths clear driver
  state for later rebind attempts.
- The timer registry returns owned timer IDs and supports explicit unregister;
  removable drivers can now tear down timer ownership.

## Partial on this branch

- The driver model is authoritative at the `Device` / `Driver` level, but some
  device-specific setup policy still lives in bus/transport helper code instead
  of clean per-driver or per-bus abstractions.
- Virtio child probing is model-driven and child resource handoff is more
  centralized, but common virtio transport, queue setup, feature negotiation,
  config harvest, and child policy remain too concentrated in
  `crates/kernel/pci-boot/src/virtio_drv.rs`.
- Virtio IRQ callback ownership has moved in the right direction, but queue
  selection, feature negotiation, and per-device config decisions still need a
  real virtio-core/bus split instead of living in `virtio_drv.rs`.
- Probe failure unwind is better for concrete cases, especially NVMe, AHCI,
  virtio-blk, virtio-input, virtio-gpu, virtio-rng, virtio-vsock, virtio-net,
  and virtio-snd, but there is no systematic devres/resource-stack mechanism
  or fault-injection proof after every step.
- Devtmpfs publication is model-owned for many real nodes, including block,
  DRM, fbdev, input, RNG, and sound, but the branch still needs an audit for
  all direct runtime `devfs::register` users.
- Sysfs exposes more Linux-shaped bus state, including `/sys/dev/char`,
  `/sys/dev/block`, parent/subsystem links, and model-backed bind/unbind attrs,
  but class-device topology and repeated bind/unbind/remove/readd behavior are
  not proven across all subsystems.
- Block, virtio-input, and virtio-rng are closest to per-device state.
  Virtio-blk supports multiple records; virtio-input supports multiple event
  devices; virtio-rng supports multiple records with one active `/dev/hwrng`
  provider. Virtio-net teardown is BDF-owned, but the runtime/netdev path still
  has a singleton installed-device slot and needs a real per-net-device table.
  Virtio-gpu teardown is BDF-owned, but the installed DRM/scanout device is still
  singleton. Virtio-vsock's upper protocol layer and virtio-snd's upper
  sound-card layer also still retain singleton limits; vsock now fails a second
  protocol publish cleanly instead of replacing the installed transport.
- UART and PS/2 platform drivers now have model probes/removes, but they are
  still intentionally singleton hardware paths, not general multi-device
  serial/input infrastructure.
- QEMU-visible runtime bind/unbind/rebind proof is incomplete. Host/unit tests
  cover pieces of the model and selected drivers, but this is not a hotplug
  certification.
- PCI enumeration is still shallow: simple QEMU devices work, but full bridge,
  multi-bus, resource assignment, and PCI runtime semantics remain incomplete.

## Open work

- Extract the rest of the real virtio bus/core split out of
  `pci-boot/src/virtio_drv.rs`. The desired shape is: PCI driver binds the
  virtio-pci function, virtio-pci creates virtio bus devices, common virtio core
  owns feature/queue transport mechanics, and child drivers bind by virtio
  device ID. Resource handoff is now centralized, but feature negotiation,
  queue programming, config harvest, MSI-X setup, and failure release helpers
  still need to move behind a `VirtioPciTransport`/`VirtioProbeState` boundary.
- Replace remaining singleton virtio child drivers with per-device state where
  the hardware class should support multiple instances: virtio-net still needs
  a full multi-netdev runtime table after its BDF-owned teardown fix; virtio-gpu
  still needs a real multi-card/scanout table after its BDF-owned teardown fix;
  virtio-vsock's upper protocol layer and virtio-snd's global sound-card layer
  are still the other main offenders.
- Add explicit fault-injection coverage for probe failure after each allocation,
  mapping, registration, IRQ/MSI step, queue setup, and userspace publication.
- Prove repeated bind/unbind/remove/readd loops under QEMU for PCI, virtio,
  block, net, DRM/fbdev, input, sound, RNG, UART, and PS/2 paths.
- Finish Linux-visible sysfs/devtmpfs/class contracts, including class parent
  relationships, `/sys/dev/{char,block}`, and stable add/remove/change uevent
  behavior across rebind.
- Generalize PCI lifecycle ownership: command enable/disable, BAR mapping
  ownership, MSI/MSI-X setup/teardown, `enable`, `driver_override`, `modalias`,
  `resource*`, and bridge topology need complete PCI-driver semantics.
- Audit all remaining direct subsystem side effects so hardware-backed device
  nodes and class devices are registered by the owning probe path and removed
  by the owning remove path.
- Add shutdown coverage distinct from remove where hardware needs a different
  quiesce path for reboot or poweroff.

## Status by area

Complete:

- Authoritative model-level bind/probe/remove state.
- PCI device publication through `device_add` plus `auto_bind`.
- Modern-only virtio-pci matching.
- Virtio transport ownership for persistent MMIO, MSI-X, and successful-probe
  vring records.
- Concrete teardown fixes for several DMA/MMIO/devnode/bottom-half leaks.

Partial:

- Per-device state.
- Class-device and device-node ownership.
- Probe unwind.
- Runtime rebind proof.
- Sysfs Linux-compatibility surface.
- PCI lifecycle semantics.

Open:

- True virtio bus/core.
- Systematic fault injection.
- Multi-device support for singleton drivers.
- QEMU hotplug/rebind certification.
- Full Linux-grade driver architecture.
