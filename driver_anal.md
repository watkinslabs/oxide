# Driver and driver-system status ledger

Date: 2026-07-04

Scope: this ledger describes the active worktree at
`/home/nd/oxide/kernel-driver-shutdown-work` on branch
`codex/driver-shutdown-work`. Do not read this document as
a statement about any other branch until these changes are committed and merged.

## Current position

This branch has moved the kernel substantially away from the old boot-probe
shape, but it is not a Linux-complete driver model yet.

Immediate priority order, as of 2026-07-04:

1. Clean up remaining driver-model/publication misplacements that affect
   userspace discovery. GNOME, systemd, udev, logind, libinput, Mesa, and ALSA
   must see real model-owned `/dev`, `/sys`, class, `dev`, `/sys/dev`, and
   uevent state. Do not add userspace-policy shortcuts in the kernel to hide
   missing driver/sysfs behavior.
2. Finish the single-machine desktop path: one virtio GPU, one input stack,
   one sound card, one root disk, and one network device. Multi-GPU,
   multi-card, and broad hotplug loops are future work unless they expose a
   bug in the single-device path.
3. Prove the actual GNOME-visible contract in QEMU/userspace: DRM/fbdev nodes,
   evdev nodes, ALSA nodes, block and net discovery, uevent delivery, and the
   `/run/udev`/seat state that makes the graphical session start.
4. Only after that path is usable, expand fault-injection, hotplug stress, and
   multi-device hardening.

Estimated branch-local status:

- Driver-core lifecycle cleanup: about 82% complete.
- Concrete driver probe/remove/shutdown cleanup: about 85% complete.
- Device publication through model-owned sysfs/devtmpfs/class state: about 70%
  complete.
- GNOME-usable single-device desktop driver path: about 60% complete.
- Full Linux-grade driver architecture, including proper bus factoring,
  hotplug, fault injection, and multi-device coverage: about 66% complete, but
  multi-device coverage is not the immediate priority.

The percentages are engineering estimates for this branch only. They are not
test-pass claims.

## Complete or substantially complete on this branch

- The old flat `DriverEntry` / `probe_all(bdf)` implementation path is gone
  from the live driver path.
- `drv::Device`, `drv::Driver`, `try_device_add`, `device_del`, `bind`,
  `bind_addr`, and `unbind` are the authoritative model path in
  `crates/drivers/drv/src/model.rs`.
- The public `drv::auto_bind` escape hatch has been removed; automatic
  attachment is internal to `try_device_add` and `register_driver`, while
  explicit binds go through the sysfs driver `bind` control path.
- PCI enumeration creates `pci` model devices with BAR resources through
  fallible model publication; NVMe, AHCI, and virtio-pci are registered as
  model drivers and attach through the driver core rather than an
  enumeration-local bind call.
- PCI model-device publication is now fallible and idempotent at the bus
  boundary: a repeated enumeration reuses the matching existing `(pci, addr)`
  device instead of panicking through publication, while identity mismatches
  are not rebound as if they were the same function.
- Model binding rejects already-bound devices, verifies bus/driver matching,
  calls `Driver::probe`, records the binding only after success, and leaves the
  device unbound when probe fails.
- Model driver registration now attaches the newly registered driver to
  existing unbound matching devices on that bus, matching Linux's
  driver-register-then-driver-attach behavior instead of requiring a separate
  enumeration pass to retry binding.
- Model driver unregistration now detaches devices bound to that driver before
  removing the driver from the registry, so `/sys/bus/<bus>/drivers/<name>`
  disappears only after the driver's `remove` callbacks have run.
- Model device publication now also attaches a newly added device to already
  registered matching drivers after devtmpfs/sysfs publication, so both
  driver-register and device-add orderings probe through the driver model
  instead of requiring call-site bind work.
- Boot-time platform devices such as serial and i8042 now rely on the same
  model-owned attach path; the remaining production explicit bind entry is the
  sysfs `/sys/bus/*/drivers/*/bind` control path.
- Model unbind calls `Driver::remove` before clearing the binding.
- `device_del` unbinds first, emits remove while the object is still visible,
  removes devtmpfs state, and then drops the device from the registry.
  The driver-core tests now assert that order directly: driver `remove`,
  sysfs remove callback while still registered, devtmpfs node deletion, then
  registry disappearance.
- `drv::shutdown_all` now walks bound model devices in reverse registration
  order and calls `Driver::shutdown` without unbinding or emitting remove
  events. The power/reboot path calls this through a boot-installed hook before
  restart, poweroff, or halt.
- Concrete shutdown callbacks now quiesce NVMe, AHCI, virtio-pci,
  virtio-blk, virtio-input, virtio-gpu, virtio-rng, virtio-vsock,
  virtio-net, virtio-snd, 8250, PL011, and i8042 keyboard paths without
  reusing hot-remove publication teardown.
- Public `register_device` bypasses and the infallible public `device_add`
  wrapper have been removed from the driver model; `try_device_add` is the
  intended publication entry.
- Sysfs bus-driver controls are backed by the model path for bind/unbind, with
  driver links, `driver_override`, `modalias`, PCI `resource`, and model-derived
  uevent environment coverage improved on this branch. Model devices with
  `dev_t` now expose a `dev` attribute and dynamic `/sys/dev/char` and
  `/sys/dev/block` reverse indexes. Model-backed `mem`, `misc`, `sound`, and
  `graphics` character devices now also publish Linux-style
  `/sys/class/<class>` symlinks and `/sys/devices/virtual/<class>/<name>`
  device directories, so `/sys/dev/char` resolves to a real device object for
  pseudo, misc, ALSA/OSS, fbdev, input, and DRM char devices. Model-backed
  virtual input, DRM, and character class devices now expose a `device`
  symlink when the class device has a real parent in the driver model.
  Sysfs/netlink tests now prove bind/unbind emits `change` uevents from the
  current model state: bound events include `DRIVER=<name>`, while unbound
  events do not carry stale driver ownership.
  Block, input, and model-backed virtual character class `uevent` attributes
  are now writable sysfs attributes rather than read-only static bodies, so
  `udevadm trigger` can re-emit root-disk, evdev, sound, graphics, misc, and
  mem device events from the current model-owned `/sys/devices/virtual/...`
  state.
  Model-backed character-class tests now also prove remove/readd of the same
  device identity and `dev_t`: class symlinks, parent `device` links, and
  `/sys/dev/char` reverse indexes disappear on `device_del` and reappear from
  the re-added model device.
- The stale procfs-era static `/sys/class/misc/autofs` registration has been
  removed; autofs sysfs state now comes from the model-owned misc device and
  exposes the same `10:235` dev_t as `/dev/autofs`.
- Built-in devfs pseudo-device publication now has a fallible
  `try_populate_defaults` path. Matching existing pseudo devices are treated
  as idempotent model state, while conflicting model devices return a driver
  model error instead of hiding publication failure inside the helper.
- Console/tty boot node publication now also has a fallible
  `try_register_devnodes` batch path. Matching existing tty model devices are
  idempotent, and conflicts roll back nodes published by the failed attempt
  before the boot wrapper reports the fatal model error.
- Boot-created platform devices for serial and i8042 now go through explicit
  `try_device_add` handling instead of the infallible convenience wrapper;
  matching existing platform identities are reused, while real conflicts are
  reported at the boot boundary.
- The public driver-core publication API no longer exports an infallible
  `device_add` wrapper. Production and cross-crate callers must handle
  `try_device_add` errors explicitly; only drv's private unit-test helper keeps
  the short name.
- PCI capability dumping is read-only again for MSI-X; MSI-X programming for
  virtio devices belongs to the virtio-pci transport probe/remove path.
- The virtio-pci transport accepts modern virtio PCI IDs only. Transitional
  IDs are not mixed into the modern cap-based path.
- Virtio-pci creates child `virtio` devices through fallible model publication,
  and child virtio drivers bind through the model.
- Virtio child model-driver declarations have been split out of the
  virtio-pci transport module into a dedicated `pci-boot::virtio_child`
  module. The PCI transport file no longer owns every child `drv::Driver`
  declaration, and child probes no longer import transport helper callbacks
  directly.
- Virtio child driver binding now goes through one bus-facing
  `VirtioChildDriver` wrapper in `pci-boot::virtio_child`. Matching by virtio
  device ID, child session begin, failed-probe transport release, successful
  transport publish, parent-key remove unpublish, and shutdown key lookup are
  centralized; per-child code supplies only profile, install, remove, and
  shutdown policy.
- Virtio child device IDs for net, block, RNG, vsock, sound, input, and GPU
  are now supplied by the child driver crates instead of being hard-coded in
  the PCI-backed virtio child bus glue. The virtio-gpu placeholder notify
  pointer marker was removed rather than preserving unused future-plumbing.
- Shared `virtio` now owns the virtio child bus/vendor matching contract
  through `VirtioChildDriverId`; each child driver exports its own descriptor,
  and the PCI-backed child wrapper consumes those descriptors instead of
  open-coding virtio bus/vendor/device matching in the glue.
- Shared `virtio` now also owns the transport-neutral child model-device
  identity contract: child bus name, synthetic `virtioN` address construction,
  modern PCI ID to virtio child ID conversion, child class, and parent-link
  matching. The virtio-pci model driver consumes that shared identity object
  for child publication/removal instead of open-coding virtio child addresses,
  device IDs, and PCI-parent scans in the transport glue.
- Shared `virtio::VirtioChildDeviceKey` now wraps the stable per-child runtime
  key exposed by `VirtioChildTransportSession`. The current PCI-backed bus
  still derives it from BDF location, but the shared child session contract no
  longer exposes a PCI-shaped `u32` as its transport-neutral identity.
- `drv-virtio-rng` now accepts and stores `VirtioChildDeviceKey` for install,
  remove, shutdown, active-device promotion, and direct probe-time entropy
  seeding. Its public lifecycle API no longer receives raw PCI-packed child
  keys from the PCI-backed virtio wrapper.
- `drv-virtio-input` now accepts and stores `VirtioChildDeviceKey` for
  install, remove, and evdev lookup. The PCI-backed child wrapper tears down
  input event queues and device records without converting the typed child key
  back into a raw PCI-shaped integer.
- `drv-virtio-vsock` now accepts and stores `VirtioChildDeviceKey` for
  install, remove, shutdown, context lookup, and RX preposting. Its remaining
  raw conversion is isolated at the `net::vsock` owner-key interface, not at
  the PCI-backed child wrapper.
- `drv-virtio-blk` now accepts and stores `VirtioChildDeviceKey` for block
  init, registry identity, hot-remove, shutdown, and its test publication
  helpers. The PCI-backed child wrapper no longer converts block child keys
  into raw PCI-shaped integers.
- `drv-virtio-net` now accepts and stores `VirtioChildDeviceKey` for modern
  init, transport state identity, netdev registration tables, TX/RX runtime
  routing, neighbor-cache ownership, hot-remove, shutdown, and hosted keyed
  tests. The PCI-backed child wrapper no longer converts net child keys into
  raw PCI-shaped integers.
- `drv-virtio-snd` now accepts and stores `VirtioChildDeviceKey` for install,
  context identity, hot-remove, shutdown, PCM-info scan, and event-handler
  teardown. Its raw conversion is isolated at the sound-core owner-key
  interface instead of the PCI-backed child wrapper.
- `drv-virtio-gpu` now accepts and stores `VirtioChildDeviceKey` for device
  table identity, install, hot-remove, shutdown, probe-failure scanout unwind,
  and scanout lifecycle teardown. BDF remains only as PCI/location metadata and
  as the existing DRM/fbdev private callback key; the PCI-backed child wrapper
  no longer converts GPU child keys into raw PCI-shaped integers.
- Shared `virtio::run_child_probe` now owns the transport-neutral child probe
  lifecycle: run child install, publish transport state only after success, and
  release failed-probe resources on child error. The PCI-backed child model
  wrapper delegates that ordering to shared virtio instead of open-coding
  publish/unwind around `VirtioChildSession`.
- Shared `virtio::VirtioProbeLease` now owns the one-shot transport-state
  lease used during child probe. The PCI-backed session uses that lease for
  both successful publish and failed-probe release, so explicit child-probe
  errors and session drop cannot double-release the same prepared transport
  state. Hosted virtio tests cover the idempotent ownership transfer.
- Shared `virtio::VirtioProbeOwnedFrames` now owns the frame ledger for a
  prepared child probe. The PCI-backed transport publishes only vring frames
  into the live transport record after success; failed child probes drain every
  still-owned frame, including net boot payload frames, without child-type
  conditional cleanup.
- Shared `virtio::run_child_remove` and `virtio::run_child_shutdown` now own
  the transport-neutral child remove/shutdown sequencing for a stable
  `VirtioChildDeviceKey`: child remove runs before transport unpublish, while
  shutdown dispatch receives the same typed key without forcing the generic
  wrapper back to raw PCI-shaped integers.
- Shared `virtio` now owns a transport-neutral
  `VirtioChildTransportSession` contract plus child location and net
  boot-payload descriptors. The current boot PCI-backed implementation lives
  in `pci-boot::virtio_bus::VirtioChildSession`, and child probes consume the
  shared session trait instead of importing `virtio_drv` transport helpers or
  naming the PCI-backed session type directly.
- The PCI-backed child session now carries an explicit
  `virtio_drv::VirtioPciTransport` backend. Child-session transport bring-up,
  publish, and unpublish calls go through that backend object; the raw
  virtio-pci probe/publish/unpublish helpers are private to the transport
  module.
- Shared `virtio::VirtioChildResourceState` now owns the transport-neutral
  child readiness and resource-publication policy: DRIVER_OK presence, common
  config presence, required queue validity, optional device config, and
  optional net boot payloads. The PCI backend supplies concrete q0-q3 resource
  descriptors and payload addresses, but no longer owns the readiness policy.
- Shared `virtio::VirtioChildProbeFacts` now carries the child-visible
  transport probe result: negotiated driver features, validated child resource
  state, and net boot payload descriptors. The PCI `VirtioProbe` now owns
  PCI/MMIO/MSI-X lifetime and opaque frame-release records, while debug-only
  probe trace fields live in `VirtioPciProbeTrace`; child sessions read the
  shared facts object instead of individual PCI probe fields.
- Virtio-pci owns persistent transport MMIO mappings, MSI-X state, and vring
  frame publication/teardown records for successful child probes.
- Virtio-pci MSI-X state is now carried as an owned optional binding instead
  of parallel zero-sentinel fields, and teardown masks the MSI-X table entry
  and disables MSI-X before dropping PCI memory decoding.
- Virtio-pci probe ownership has started moving behind an explicit
  `VirtioProbeState`: transport mappings, common/device config windows, and
  MSI-X binding are now consumed through probe-state finalization, and notify
  VA mapping/kick operations go through probe-state methods instead of direct
  mapping mutation from the main probe body.
- The shared virtio resource handoff exists through `VirtioResources` and
  `VirtQueueResource`, with queue lookup validation centralized through
  `require_queue`. Child probes now ask `VirtioProbe` for resources by their
  declared `VirtioChildRequirements`, and `VirtioProbe` builds the resource set
  from the required queue bitmap instead of each child glue path manually
  selecting q0/q1/q2/q3. The resource object now also carries the generic
  transport-mapped `DEVICE_CFG` window, so child drivers can parse their own
  device-specific config.
- Virtio extra queue setup is now described by a transport queue plan instead
  of hard-coded `needs_q1` / `needs_q2` / `needs_q3` dispatch in the virtio-pci
  probe path. Shared `virtio::queue_cfg` now owns the common-cfg queue
  programming protocol, and the virtio-pci transport helper supplies the
  current PMM/HHDM-backed queue allocator adapter.
- Virtio child transport profiles now use shared `virtio::VirtioTransportProfile`
  and `virtio::VirtioQueuePlan` types. BAR-derived transport mappings,
  PMM/HHDM-backed virtqueue frame allocation/zeroing, notify-window mapping,
  notify kicks, q0 post-kick status/used-ring observation, child-declared
  early payload policy, net boot-buffer posting/allocation, ISR read-to-clear
  sampling, MSI-X table binding/release,
  runtime transport-record lifetime, and failed-probe frame release are now
  owned by a dedicated virtio-pci transport helper or probe-state method
  instead of the probe body. The child-declared feature/queue/notification
  requirements are no longer pci-boot-local structs.
- Modern virtio common-cfg reset/status transitions, feature negotiation,
  FEATURES_OK validation, DRIVER_OK publication, and queue-size scanning now
  live in the shared `virtio::common_cfg` helper. Shared virtio now also owns
  the generic common-cfg bring-up wrapper that negotiates, scans queues, calls
  a transport queue-programming callback, and publishes DRIVER_OK or FAILED,
  instead of leaving that ordering as pci-boot-private state.
- Mandatory q0 plus planned extra virtqueue programming now uses a shared
  queue-set helper with allocator-driven frame ownership and partial-allocation
  unwind, so the virtio-pci probe body no longer hand-rolls q1/q2/q3
  programming loops. Queue notify VA lookup and queue notify writes now go
  through the virtio-pci transport helper, and planned extra-queue notify
  mappings are resolved by `VirtioProbeState` rather than an open q2/q3 loop
  in the probe body. The old virtio-net probe-time dummy TX kick is gone; net
  boot-buffer posting/allocation now uses helper calls. Net/vsock q1 notify
  policy is explicit in the probe profile and q1 notify mapping goes through
  `VirtioProbeState`.
- Virtio-pci `VirtioProbeState` now owns the ordering that ties feature
  negotiation, queue-size scanning, MSI-X binding, queue programming, and
  DRIVER_OK publication into one transport bring-up result. The probe body
  records the result and handles child-specific resource publication rather
  than sequencing the common transport protocol directly.
- Virtio-pci runtime HHDM context now lives in an explicit
  `VirtioPciRuntime` value. Queue programming, net boot-buffer
  posting/allocation, used-ring sampling, and child resource facts consume the
  same transport runtime context instead of recomputing or passing raw HHDM
  offsets through unrelated probe code.
- Planned virtio-pci extra-queue notify mappings are now stored by queue index
  instead of hard-coded q2/q3 fields, removing another queue-number special
  dispatch from the transport handoff path.
- Shared virtio child transport profiles now store queue plans by virtqueue
  index up to the shared resource queue limit instead of using a compact
  q1/q2/q3 side table. The PCI transport consumes that indexed profile for
  MSI-X binding, common-cfg queue programming, and planned notify mappings.
- The old q1-specific notify policy enum is gone. Persistent child queue
  notify mappings now come from the indexed queue plan itself, while the
  remaining net boot TX buffer allocation is tied to the child-declared early
  payload policy instead of a queue-number-specific dispatch.
- Shared virtio now owns indexed notify-mapping descriptors and the
  child-visible `VirtQueueResource` assembly from scanned queue sizes,
  programmed queues, and transport-resolved notify VAs. The PCI transport
  still maps/kicks hardware notify windows, but no longer owns the generic
  queue-resource handoff builder or the child queue-plan policy for resolving
  persistent planned notify mappings.
- Shared virtio now owns final runtime handoff assembly through
  `VirtioRuntimeHandoff`: final notify mappings, child-visible queue resource
  records, net boot payload descriptors, and q0 kick/ISR/used-ring trace facts
  are built from transport-provided observations instead of PCI-local resource
  structs.
- Shared `virtio::VirtioTransportProbeResult` now owns the transport-neutral
  completed-probe result: child-facing facts, child resource state assembly,
  vring cleanup frame extraction, and net boot payload frame extraction. The
  PCI transport keeps PCI/MMIO/MSI-X lifetime and PCI debug trace state only.
- Virtio child drivers now export their own `VirtioTransportProfile`
  declarations, including feature masks, queue requirements, and child IRQ
  callback policy. The pci-boot virtio child bus glue consumes those profiles
  instead of constructing child policy locally.
- Shared `virtio::ProgrammedQueues` now exposes indexed queue lookup, and
  virtio-pci resource handoff assembles child-visible queue resources over the
  shared resource queue count instead of expanding q2/q3 resource locals in
  pci-boot. Planned notify mappings use the same shared queue count and
  indexed programmed-queue lookup.
- Virtio-pci debug probe trace now carries the same indexed
  `VirtQueueResource` handoff records used by child publication instead of
  duplicating q0/q1 descriptor and notify fields in a trace-only structure.
- The PCI-backed virtio child session now owns failed-probe transport cleanup
  as an idempotent session lifetime rule: unpublished sessions release their
  transport on explicit failure or drop, while published sessions transfer
  ownership to the runtime transport record.
- Child probe readiness checks for DRIVER_OK, required queue indexes, device
  config, and net boot payloads now go through shared
  `virtio::VirtioChildRequirements` evaluated by
  `VirtioProbe::child_resources` instead of per-driver open-coded guards and
  resource lists. Virtio-snd now requires all four of its transport queues
  before child install, and pci-boot validates required queues through
  `VirtQueueResource::is_runtime_valid`.
- Virtio common-cfg now has an explicit FAILED status helper, and virtio-pci
  transport bring-up marks the device FAILED when FEATURES_OK is rejected or
  mandatory q0 programming fails instead of leaving the device in a partial
  non-DRIVER_OK state.
- Failed virtio child probes now release transport vring frames through the
  probe's recorded queue state instead of per-driver hand-written q0/q1/q2/q3
  frame lists; child-owned payload frames are passed as explicit extras.
- Virtio-net's late netdev registration failure now unwinds through the
  transport failed-probe release path after the child runtime is uninstalled,
  so transport-owned vring frames are reset/freed instead of only unmapping
  probe MMIO.
- Virtio-blk no longer has PCI-transport-owned block config harvest. The
  virtio-pci path maps the device config as a generic resource, and the
  virtio-blk child driver reads capacity/block-size during its own probe.
- Virtio-net's device-specific wanted feature mask now lives in the
  virtio-net child driver; virtio-pci still executes common-cfg negotiation
  but no longer carries the net MAC/STATUS feature policy itself.
- Virtio-gpu's wanted feature mask now comes from the virtio-gpu child driver
  instead of the transport using a generic VERSION_1-only profile, so GPU
  feature negotiation matches the child driver's advertised capability policy.
- Virtio-blk's wanted feature mask now lives in the block child driver and
  includes `VIRTIO_BLK_F_BLK_SIZE`, so the child-owned config parser can use
  the device's native block size when the device offers it.
- Virtio-input, virtio-rng, virtio-vsock, and virtio-snd now also expose their
  wanted feature masks from the child drivers. The PCI transport no longer has
  a generic VERSION_1-only child feature policy for the active virtio profiles.
- Virtio-pci MSI-X setup now names the virtio `NO_VECTOR` sentinel, records the
  q0 queue vector in the MSI-X binding, and clears the MSI-X function mask when
  enabling the programmed table entry instead of relying on an implicit
  entry-0 convention. The binding helper now accepts a requested MSI-X table
  entry and validates it against the decoded table size, so q0 is just the
  first policy user rather than a hardcoded special case. Transport MSI-X
  ownership is now plural, so published and failed probes release all bound
  table entries instead of a single optional binding. Extra queue plans now
  carry explicit per-queue IRQ callback policy, and virtio-pci resolves that
  policy into transport-owned MSI-X bindings before common-cfg queue
  programming instead of hardcoding `NO_VECTOR` into every extra queue plan.
- Virtio-vsock no longer has PCI-transport-owned guest-CID harvest. The
  virtio-vsock child driver reads its own CID from the generic `DEVICE_CFG`
  resource during install. The dead pci-boot `virtio_vsock_cfg` pass-through
  has been removed, so vsock install goes directly through the child driver.
  Its failed install path now owns the reserved upper endpoint plus RX/TX
  bounce frames as one probe state until the installed transport takes them.
- Virtio-snd no longer has PCI-transport-owned sound config harvest. The
  virtio-snd child driver reads jacks/streams/chmaps/controls from the generic
  `DEVICE_CFG` resource before querying PCM stream info. Its virtio-pci profile
  now plans the required EVENTQ(1) alongside CONTROLQ/TXQ/RXQ, maps q1's notify
  window, assigns q1 a child-owned MSI-X callback, and hands the event queue
  resource to the child driver instead of silently programming only q0/q2/q3.
  The child driver now preposts writable event descriptors, drains EVENTQ from
  a sound softirq, recycles used descriptors back onto avail, and tracks raw
  drained-event diagnostics. The dead pci-boot `virtio_snd_cfg` pass-through
  has been removed, so sound install goes directly through the child driver.
  Its probe scratch/event/TX/RX frames are now owned as one probe-frame set
  until the installed sound context takes teardown ownership.
- Virtio-input no longer has PCI-transport-owned input config VA handoff. The
  input child driver reads identity and capability data from the generic
  `DEVICE_CFG` resource during its own install path. It now also owns
  `/dev/input/eventN` publication and removal from the child install/remove
  path instead of having the virtio-pci glue reach into the evdev devtmpfs
  helper.
- Virtio-net no longer has PCI-transport-owned MAC config harvest. The
  virtio-net child driver reads its MAC address from the generic `DEVICE_CFG`
  resource during its own install path.
- Virtio-blk has per-device records, unregisters disks on remove, freezes new
  I/O, waits for its single in-flight request owner, resets the device, and
  returns child-owned bounce allocation when safe. Its child API is keyed by
  the packed parent device key, and the dead pci-boot `virtio_blk_cfg`
  pass-through has been removed so block install/remove/shutdown go directly
  through the child driver.
- NVMe and AHCI now bind through model probes and keep typed block-device state;
  remove unregisters disks, quiesces hardware state, and returns queue/bounce
  frames. Their BAR mappings are owned and dropped on probe failure/remove.
  NVMe publication is now per PCI function instead of a process-wide singleton:
  successful probes allocate `nvmeXn1` names, record the bound BDF key, reject
  duplicate binds before controller bring-up, and route remove/shutdown through
  the device model's BDF.
  AHCI publication is also now per PCI function: successful probes allocate
  Linux-style `sdX` names, record the bound BDF key, reject duplicate binds
  before HBA bring-up, route remove/shutdown through the device model's BDF,
  and publish the ATA IDENTIFY serial into the block registry for by-serial
  lookup instead of using a fake shared identity.
- Virtio-input supports multiple input device records, publishes
  `/dev/input/eventN` through model-owned devices, generates
  `/proc/bus/input/devices` from live input state, and clears its event-queue
  bottom half when the last queue is removed. Shutdown now calls an explicit
  event-queue quiesce path instead of the hot-remove-named helper. Hot-remove
  and shutdown now address event-queue drain state by the owning virtio child
  key directly, so missing input metadata cannot strand queue buffers or the
  shared input bottom-half handler. `/proc/bus/input/devices` now advertises
  the same `/devices/virtual/input/eventN` sysfs path that the input class
  actually publishes, so libinput/udev metadata no longer points at a dead
  pre-model topology.
  Evdev now handles `EVIOCGRAB` as Linux per-open-file state: grabs are keyed to
  the open `File`, competing grabs fail with `EBUSY`, non-owners do not drain or
  poll events while another client owns the grab, and last close releases the
  grab. `EVIOCSCLOCKID` now validates the requested userspace clock id instead
  of blindly acknowledging it, and `EVIOCREVOKE` marks the current open file
  revoked so later reads fail with `ENODEV`. VFS read/poll/release dispatch now
  has file-aware hooks so this lives in the same layer Linux uses
  (`struct file`/`file_operations`) rather than in inode-global shortcuts.
- Virtio-gpu remove is keyed to the owning virtio child key and tears down
  fbcon/fbdev/DRM/klog/tty scanout state before backing memory is released.
  Probe-failure unwind only removes scanout state for the failed child key.
  Hot-remove now attempts console/fbdev unpublish, primary DRM/device
  unregister, and scanout allocation cleanup independently, so a missing
  primary GPU table entry cannot leave child-owned scanout state behind.
  Installed virtio-gpu device state is now a per-child-key table, duplicate
  child-key install is rejected before publication, and DRM card IDs are
  stable slots so unregistering one card does not renumber the remaining
  devices.
  DRM now publishes card/render device nodes per stable card slot
  (`/dev/dri/cardN`, `/dev/dri/renderD128+N`), encodes the card id in the DRM
  inode tag, routes card-backed ioctls through the matching backend slot, and
  builds `/sys/class/drm` plus `/sys/devices/virtual/drm` from live DRM
  `drv::try_device_add` records instead of a static card0 table.
  Scanout backing state is also a BDF-keyed table now. DRM SETCRTC/PAGE_FLIP
  runtime hooks, scanout ownership, last-close restore, and flip-event queues
  are keyed by DRM card id and routed to the owning virtio-gpu BDF. DRM dumb
  buffers and FB metadata are now card-owned too: CREATE/MAP/DESTROY/ADDFB/RMFB,
  mmap cookie lookup, and SETCRTC/PAGE_FLIP FB resolution all require the
  matching card id, and DRM unregister drops that card's CRTC and dumb-buffer
  table state. fbdev flush/blank operations are now stored on each `/dev/fbN`
  record and call back into the owning virtio-gpu BDF instead of a global
  display hook; virtio-gpu scanout context now records the exact published
  fbdev index and unpublishes by that owner token instead of searching by
  framebuffer base address. Console/fbdev publication is transactional around
  that stored index, so failed fbdev publication releases console ownership
  before global fbcon/klog/tty hooks are installed. Shutdown quiesces the
  scanout context in place and resets the device without dropping fbdev
  publication or framebuffer allocation metadata, so a later remove can still
  consume the correct owner token and free the backing. fbcon publication
  still has one explicit foreground console owner. Dumb-buffer mmap now pins
  the DRM object through a file-backed shared VMA and PMM object refs, so
  DESTROY_DUMB/card unregister cannot return pages while userspace VMAs can
  still fault them.
  The display-info probe command buffer and scanout framebuffer run are now
  owned probe objects; early parse/no-display/setup failures release them
  through drop, and successful scanout setup explicitly transfers those frames
  to scanout teardown ownership.
- Virtio-net owns netdev publication/removal and RX runtime
  installation/removal: iface/IP bottom-half state, ARP-GC timer, and `NetRx`
  handler are installed from the net driver path and removed after reset. Netdev
  registration and unregistration now happen inside virtio-net child
  install/remove rather than in the virtio-pci glue. The old boot-probe default
  IPv4 policy is gone; the RX path learns IPv4 state from normal address
  configuration hooks. Virtio-net install/remove is now keyed to the owning
  virtio child key, so a remove for another device cannot clear another
  transport.
  TX/RX queue cursors now live in keyed installed-device records, the TX
  primitive has a BDF-keyed entry point, and the published `NetDev` carries its
  owning device key. Registered iface ownership and RX softirq runtime state
  are keyed tables too, so softirq drains, ARP replies, and ARP/NDP neighbor
  solicitations transmit through the device that owns the registered netdev.
  Netdev visible names are allocated as `ethN` per runtime record, RX stats are
  per netdev, and IPv4 ARP cache entries are owned by the transmitting/receiving
  virtio-net runtime instead of a process-global cache.
  Hot-remove now clears registered netdev publication, interface runtime, and RX
  softirq runtime by child key even when the primary virtio-net transport record
  is already gone. The shared `NetRx` bottom-half handler and ARP-GC timer now
  stay installed until the last RX runtime is removed instead of following a
  single primary transport record.
  IPv6 NDP is stack-owned in kernel builds: RX learning goes through
  `deliver_rx_ipv6`, and virtio-net TX resolves neighbors through the
  registered interface's stack NDP table. The virtio-pci net probe no longer
  rejects a second net device before child install, so admission now reaches
  the keyed net child path instead of a transport-side singleton gate.
- The core IPv6 stack NDP cache is no longer a process-global `ip -> mac` map.
  Stack-side NDP learning is keyed by `(iface, IPv6 address)`, so duplicate
  link-local neighbors on different interfaces no longer overwrite each other.
- Virtio-vsock remove is keyed to the owning virtio child key and clears its
  `VsockRx` bottom half only for the installed transport. The upper
  `net::vsock` layer now stores owner-keyed protocol endpoint records with
  per-owner guest-CID/TX hooks, rejects duplicate owner or guest-CID
  publication, and keeps transport state as keyed records instead of an
  implicit single slot. Quiesced endpoints keep their reservation for ordered
  remove/unwind, but no longer report as the live compatibility owner or hide a
  remaining live endpoint. AF_VSOCK bind now honors a specific local
  `sockaddr_vm.svm_cid` by resolving it to the owning live endpoint; bound
  connect/listen/accept paths carry that owner, listener backlogs are keyed by
  `(owner, port)`, and `VMADDR_CID_ANY` remains the wildcard compatibility
  route. AF_VSOCK socket close now removes listener state, drops pending
  accept backlog connections, and closes connected records instead of leaving
  global protocol-table state behind.
  Remove/shutdown now remove or quiesce the owner-keyed protocol endpoint even
  when the primary transport context is already gone.
- Virtio-rng now keeps per-child-key records, seeds from the just-bound device,
  removes by owning virtio child key, owns `/dev/hwrng` publication/removal
  inside the RNG child driver, and promotes `/dev/hwrng` publication to a
  remaining RNG device on active-provider removal. Virtio-snd install/remove is
  now keyed to the owning virtio child key and releases child-owned
  queue/buffer resources only for the matching transport; the sound card layer
  allocates owner-keyed ALSA card numbers, publishes per-card ALSA/OSS nodes,
  routes ops by the card owner, rejects unregister from non-owners, and keeps
  raw EVENTQ drain accounting keyed by the transport owner. Remove now clears
  sound-core card and ops publication by owner even when the primary transport
  context is already gone. The old EVENTQ
  globals are aggregate compatibility diagnostics only. Virtio-gpu duplicate
  child-key admission is also left to the child install
  path.
- Virtio MSI-X handler ownership is no longer selected by a transport-side
  PCI-ID special-case dispatch. Child virtio driver probes now pass the
  optional queue-0 IRQ callback into the virtio-pci setup path; the PCI
  transport still owns MSI-X table/vector programming and teardown.
- Virtio-pci now clears PCI MEM/BUS_MASTER and drops probe-owned mappings on
  early transport probe exits after command enable, so missing COMMON_CFG or
  unusable COMMON BAR decode no longer leaves the PCI function enabled.
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
  centralized, and extra queue setup is now data-driven. Virtio-blk,
  virtio-vsock, virtio-snd, virtio-input, and virtio-net config parsing have
  moved into their child drivers, and net early payload policy is now declared
  by the child transport profile. Common virtio transport and some child
  policy still remain too concentrated in
  `crates/kernel/pci-boot/src/virtio_drv.rs`.
- Virtio IRQ callback ownership has moved in the right direction, and queue
  selection no longer uses per-queue special-case booleans, but feature
  negotiation and per-device config decisions still need a real
  virtio-core/bus split instead of living in `virtio_drv.rs`.
- Probe failure unwind is better for concrete cases, especially NVMe, AHCI,
  virtio-blk, virtio-input, virtio-gpu, virtio-rng, virtio-vsock, virtio-net,
  and virtio-snd. Virtio failed-probe frame ownership is now centralized in a
  transport-owned frame ledger, but there is still no general devres stack or
  fault-injection proof after every step.
- Devtmpfs publication is model-owned for real hardware-backed nodes,
  including block, DRM, fbdev, input, RNG, sound, console/tty, and boot pseudo
  char devices. The remaining direct `devfs::register` users are fixed
  namespace entries, devpts allocation, coredump artifacts, or other
  non-hardware pseudo-files rather than driver-owned device nodes.
- Driver-owned devnode registries for block, evdev, fbdev, DRM card/render
  nodes, and the active virtio-rng `/dev/hwrng` provider now have hosted
  remove/readd loop proofs: unregister/remove deletes the model device(s),
  re-register/re-publish recreates exactly one owned model device per node,
  block `dev_t` lookup disappears and returns with the disk, and registry slots
  do not remain stuck after normal remove.
- Sysfs exposes more Linux-shaped bus state, including `/sys/dev/char`,
  `/sys/dev/block`, parent/subsystem links, class-device `device` links for
  model-parented input/DRM/virtual character devices, virtual root mappings
  for block/input/DRM reverse-dev indexes, and model-backed bind/unbind attrs,
  plus direct proofs for bind/unbind change uevents and model-backed
  character-class remove/readd. Repeated bind/unbind/remove/readd behavior is
  still not proven across all subsystems.
- Block, NVMe, AHCI, virtio-input, and virtio-rng are closest to per-device state.
  Virtio-blk supports multiple records; virtio-input supports multiple event
  devices; virtio-rng supports multiple records with one active `/dev/hwrng`
  provider. NVMe now supports multiple per-BDF controller records and unique
  block names, and AHCI now supports multiple per-BDF controller records with
  unique `sdX` block names, but both still need QEMU multi-controller
  bind/unbind/rebind proof.
  Virtio-net transport, registered-iface, TX, RX softirq runtime,
  visible naming, RX stats, IPv4 ARP cache state, and IPv6 NDP stack lookups
  are now BDF/interface-owned keyed records, exported virtio-net TX/RX helper
  entry points require an owning device key, and the core net stack's NDP table
  is keyed by interface. Virtio-net still needs live multi-device bind/unbind
  proof.
  Virtio-gpu installed device state, DRM backend records, DRM card/render
  nodes, DRM ioctl backend routing, scanout backing records, DRM runtime
  scanout hooks, scanout owner tokens, flip-event queues, and dumb-buffer/FB
  object lookup are BDF/card owned. Display-info and negotiated-feature
  helpers are now BDF-keyed instead of selecting the first installed GPU.
  fbdev flush/blank hooks are per-fb records keyed to the owning BDF, while
  fbcon remains a single foreground console bound to an explicit owner.
  Virtio-vsock's upper protocol endpoint records are now owner-keyed, CID-bound
  socket paths select the matching live endpoint, listener/connection close
  paths release protocol-table state, and the compatibility AF_VSOCK socket
  path still selects one primary endpoint for unspecified connects. Virtio-snd
  now keys ALSA card publication,
  playback/capture/OSS substream runtime state, and ops routing to the owning
  transport, publishing `controlC<N>`/`pcmC<N>D0*` nodes with stable card
  numbers instead of selecting the first installed context. It still needs
  QEMU live multi-card bind/unbind/rebind proof and broader event/control
  coverage.
- UART and PS/2 platform drivers now have model probes/removes, but they are
  still intentionally singleton hardware paths, not general multi-device
  serial/input infrastructure.
- QEMU-visible runtime bind/unbind/rebind proof is incomplete. Host/unit tests
  cover pieces of the model and selected drivers, but this is not a hotplug
  certification.
- PCI enumeration/lifecycle is still shallow: simple QEMU devices work, PCI
  model-device publication no longer panics on repeated enumeration of the
  same function, and bound AHCI/NVMe/virtio paths now clear MEM/BUS_MASTER on
  teardown/failure, but full bridge, multi-bus, resource assignment, and PCI
  runtime semantics remain incomplete.
- Central shutdown dispatch exists, and the main storage, virtio, serial, and
  PS/2 keyboard devices now have hardware-specific quiesce paths. A current
  source audit shows the remaining default no-op `Driver::shutdown` users are
  test-only model drivers; production model drivers registered on this branch
  have explicit shutdown callbacks.

## Open work

- Extract the rest of the real virtio bus/core split out of
  `pci-boot/src/virtio_drv.rs`. The desired shape is: PCI driver binds the
  virtio-pci function, virtio-pci creates virtio bus devices, common virtio core
  owns feature/queue transport mechanics, and child drivers bind by virtio
  device ID. Resource handoff is now centralized and carries the common
  `DEVICE_CFG` window; virtio-blk, virtio-vsock, virtio-snd, virtio-input,
  and virtio-net config parsing have moved into their child drivers. The
  common-cfg status/reset/feature/queue-size register protocol and generic
  common-cfg bring-up state machine now live in shared `virtio::common_cfg`;
  common queue programming now lives in shared
  `virtio::queue_cfg` behind a transport-provided allocator; BAR-derived
  transport mappings, PMM/HHDM-backed virtqueue frame allocation/zeroing,
  MSI-X table binding/release, runtime transport-record publish/unpublish,
  failed-probe frame release, ISR read-to-clear sampling, q0 post-kick
  status/used-ring observation, net boot-buffer mechanics, and notify VA/kick
  mechanics now live in a dedicated virtio-pci transport helper, while the
  net early payload requirement is child-declared in the shared transport
  profile. A first
  `VirtioProbeState` owns config windows and transport lifetime through
  finalization/state methods. Shared virtio resolves indexed planned notify
  mappings from child queue plans, while PCI supplies only the concrete
  notify-offset-to-VA mapper. Common transport bring-up ordering also now goes
  through `VirtioProbeState`.
  Child readiness validation is described by shared
  `virtio::VirtioChildRequirements` and evaluated by
  `virtio::VirtioChildResourceState`; child transport profiles and queue plans
  now use shared `virtio::VirtioTransportProfile` and
  `virtio::VirtioQueuePlan`; early payload policy is child-declared in
  `virtio::VirtioEarlyPayloadPolicy`; resource publication for child probes
  now uses shared readiness/resource assembly instead of per-child q0/q1/q2/q3
  lists in the PCI glue; final runtime handoff assembly now uses shared
  `virtio::VirtioRuntimeHandoff` instead of a PCI-local resource struct; and
  child-owned transport-profile declarations keep feature, queue, and child
  IRQ policy in the child driver crates. Virtio child model-driver declarations
  now live in a separate `pci-boot::virtio_child` module instead of the
  virtio-pci transport module, and child probes now use the shared
  `virtio::VirtioChildTransportSession` trait implemented by
  `pci-boot::virtio_bus::VirtioChildSession` instead of importing
  `virtio_drv` transport helpers directly; per-child probe callbacks no
  longer name the PCI-backed session type. That child module now uses one
  generic `VirtioChildDriver` wrapper for model-driver matching, session
  lifetime, failed-probe release, publish, unpublish, and shutdown key lookup,
  leaving per-child ops focused on device policy. Child virtio device IDs are
  now exported by the child driver crates and consumed by that wrapper instead
  of living as literals in the PCI-backed bus glue. The shared
  `virtio::VirtioChildDriverId` descriptor now owns virtio child
  bus/vendor/device matching, with descriptors exported by the child driver
  crates and consumed by the wrapper. Shared `virtio` also owns virtio child
  model-device identity, synthetic child address construction, modern PCI ID
  conversion, and parent-link matching; virtio-pci consumes that helper for
  child model-device publication/removal instead of keeping those identity
  rules in PCI transport code. The shared child session contract now exposes a
  typed `virtio::VirtioChildDeviceKey` rather than a raw PCI-packed `u32`; the
  current PCI-backed implementation derives that key from its BDF location and
  `drv-virtio-rng` now consumes that typed key directly for install, remove,
  shutdown, and probe-time direct entropy reads. `drv-virtio-input` now also
  consumes that typed key directly for install, event-queue runtime identity,
  remove, shutdown, and evdev lookup.
  `drv-virtio-vsock` now consumes it directly for install, remove, shutdown,
  context lookup, and RX preposting, while converting to raw only at the
  `net::vsock` owner-key boundary. `drv-virtio-blk` now consumes the typed key
  directly for init, registry identity, hot-remove, shutdown, and test
  publication helpers. `drv-virtio-net` now consumes it directly for modern
  init, transport state identity, netdev registration tables, TX/RX runtime
  routing, neighbor-cache ownership, hot-remove, shutdown, and hosted keyed
  tests. `drv-virtio-snd` now consumes it directly for install, context
  identity, hot-remove, shutdown, PCM-info scan, and event-handler teardown,
  while converting to raw only at the sound-core owner-key boundary.
  `drv-virtio-gpu` now consumes it directly for install, device-table identity,
  hot-remove, shutdown, scanout teardown, and probe-failure scanout unwind. The
  PCI-backed virtio bus wrapper no longer unwraps child keys for GPU or
  transport unpublish; raw conversion for unpublish is isolated inside the PCI
  transport backend where the current BDF-derived table key lives. Shared
  `virtio::run_child_probe` now
  owns child-probe publish/unwind ordering, so the PCI-backed wrapper no
  longer hand-codes successful transport publication versus failed child-probe
  release. Shared `virtio::run_child_remove` and
  `virtio::run_child_shutdown` also own remove-before-unpublish and shutdown
  dispatch ordering for typed child keys. The PCI-backed session now carries an
  explicit `virtio_drv::VirtioPciTransport` backend, and raw probe, publish,
  and unpublish helpers are private to that transport module. The
  shared `virtio::VirtioChildResourceState` now owns child readiness/resource
  publication checks across transports. Shared
  `virtio::VirtioTransportProbeResult` now builds
  `virtio::VirtioChildProbeFacts` and owns the transport-neutral vring/net
  payload cleanup frame lists. Backend debug/trace-only probe-result state has
  been split into
  `VirtioPciProbeTrace`, and `VirtioProbe` now keeps opaque vring/net payload
  frame-release lists instead of individual child queue PA fields, so it is
  closer to a PCI transport lifetime object instead of a mixed
  diagnostic/resource bag. The probe result now carries child queue handoff as
  indexed `VirtQueueResource` records instead of a flattened pile of q0/q1/q2/q3
  physical-address fields. Runtime handoff observation for q0 kick/status,
  net boot payload buffers, q1 notify mapping, ISR sampling, used-ring
  sampling, and queue-resource assembly now runs through a single
  `VirtioProbeState` handoff builder instead of scattered local state in the
  main probe body. COMMON_CFG and DEVICE_CFG BAR-window setup now belongs to
  `VirtioProbeState::from_caps`, including required COMMON_CFG failure unwind,
  instead of being hand-mapped in `virtio_init_arch`. PCI config-space
  acquisition, virtio cap decode, BAR decode, and MEM/BUS_MASTER enable now
  live in `VirtioPciAcquisition`, leaving the main probe path closer to
  transport acquisition followed by virtio bring-up. The old `virtio_init_arch`
  free helper is gone; child probe now enters through `VirtioPciTransport` and
  the acquired PCI transport object drives the final probe sequence.
  Transport-level feature/q0 failure now sets FAILED. One late virtio-net
  child-unwind leak has been fixed, active virtio child feature and early
  payload policy have moved to child drivers, and failed-probe transport
  release is now owned by
  `VirtioProbe` instead of ad-hoc per-device wrappers. `VirtioProbe` now drains
  a single transport-owned frame ledger on child failure, so net boot payload
  frames cannot be leaked by a child-requirement mismatch. MSI-X q0 vector
  policy is now explicit, including function-mask handling and table-entry
  validation.
  Transport-owned MSI-X binding lifetime now handles multiple entries, and
  extra queue plans now resolve declared IRQ callbacks into queue-indexed
  MSI-X table entries before common-cfg queue programming. Virtio-snd now
  programs, owns, and drains its required EVENTQ(1) resource. Dead pci-boot
  child install pass-throughs are gone for block, vsock, and sound.
  Virtio child remove paths now always unpublish the parent transport record
  for a bound child after attempting child-specific teardown, so stale MMIO,
  MSI-X, or vring ownership cannot survive merely because a child driver's
  state table was already missing.
  Sound card ALSA/OSS node publication is now fallible as a batch: each node
  is published through `try_device_add`, partial publication rolls back already
  visible nodes in reverse order, and failed publication clears card ops and
  substream runtime state before probe can report success.
  Sound card-number reservation is now separate from published-card teardown:
  failed virtio-snd probe paths cancel only unpublished reservations, while
  `sound::unregister_card` owns published ALSA/OSS node removal, substream
  unregister, and sound-ops clearing for the removed owner.
  Virtio-snd uninstall calls that owner cleanup before requiring the transport
  context, so stale public card state is not stranded by a missing CTX record.
  Raw EVENTQ drain/accounting is now owner-keyed; higher-level sound event
  interpretation/publication, remaining child-probe failure unwind audit, and
  fault-injection proof still need to move behind a fuller `VirtioPciTransport`
  boundary.
- Replace remaining singleton hardware-backed drivers with per-device state where
  the hardware class should support multiple instances: virtio-net now has
  keyed transport, RX runtime, name/stat, IPv4 ARP cache state, and
  stack-owned interface-scoped IPv6 NDP lookup. Its shared RX bottom-half/timer
  lifetime is last-runtime-owned, but virtio-net still needs live loop proof
  and broader multi-NIC validation; virtio-gpu now has per-card DRM
  card/render nodes, ioctl backend routing, KMS scanout hooks, scanout owner
  state, flip events, dumb-buffer/FB object lookup, and per-fb owner-keyed
  fbdev flush/blank dispatch, exact fbdev-index publication ownership,
  independent primary/scanout hot-remove cleanup, and dumb-buffer mmap VMA
  lifetime pins;
  virtio-vsock now has owner-keyed endpoint records, CID-bound socket/device
  selection, owner-keyed listener backlogs, primary-context-independent
  endpoint remove/quiesce, and quiesced endpoints no longer mask another live
  transport through the primary compatibility route;
  virtio-snd's
  ALSA card nodes, playback/capture/OSS substream runtime state, and ops
  routing are owner-keyed and primary-context-independent uninstall clears
  stale sound-core publication, but it still needs live multi-card proof and
  broader sound event/control coverage. AHCI and NVMe still need live
  multi-controller proof, but they no longer use process-wide
  installed-controller slots.
- Add explicit fault-injection coverage for probe failure after each allocation,
  mapping, registration, IRQ/MSI step, queue setup, and userspace publication.
- Prove repeated bind/unbind/remove/readd loops under QEMU for PCI, virtio,
  block, net, DRM/fbdev, input, sound, RNG, UART, and PS/2 paths. Hosted
  driver-owned devnode remove/readd loops now cover block, evdev, fbdev, DRM
  node registries, and virtio-rng hwrng publication, but they are not a
  substitute for QEMU hotplug/rebind proof.
- Finish Linux-visible sysfs/devtmpfs/class contracts, including the remaining
  class parent relationships and stable add/remove/change uevent behavior
  across rebind beyond the current driver-core remove-order, sysfs
  bind/unbind change-event, and character-class remove/readd proofs.
  `/sys/dev/{char,block}` and the core
  `/sys/bus/<bus>/drivers/<driver>` bind/unbind/device-link shape exist, and
  driver-directory device symlinks resolve back to the canonical
  `/sys/devices/...` object.
- Generalize PCI lifecycle ownership: command enable/disable is now covered for
  the main AHCI/NVMe/virtio paths, and virtio MSI-X teardown now releases the
  transport-owned binding before PCI memory decode is dropped. BAR mapping
  ownership, broader MSI/MSI-X setup/teardown proof, `enable`, and bridge
  topology still need complete PCI-driver semantics. `driver_override`,
  `modalias`, the aggregate PCI `resource`, and indexed `resourceN` BAR
  attributes are model-derived sysfs state.
- Audit all remaining direct subsystem side effects so hardware-backed device
  nodes and class devices are registered by the owning probe path and removed
  by the owning remove path.
- Add concrete per-driver shutdown coverage where hardware needs a different
  quiesce path from hot-unplug remove, and prove it on reboot/poweroff paths.

## Status by area

Complete:

- Authoritative model-level bind/probe/remove state.
- Central model-level shutdown dispatch from reboot/poweroff/halt.
- PCI device publication through `try_device_add`, with driver attachment owned
  by the driver core.
- Modern-only virtio-pci matching.
- Virtio transport ownership for persistent MMIO, MSI-X, and successful-probe
  vring records.
- Concrete teardown fixes for several DMA/MMIO/devnode/bottom-half leaks.
- Sound card node publication rollback on model-device conflicts.

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

## Earlier baseline analysis from main

Driver and driver-system correctness analysis

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

At the earlier baseline, the architecture was split between two worlds:

1. An older flat `DriverEntry` / `probe_all(bdf)` path in `crates/drivers/drv/src/lib.rs`.
2. A newer `Device` / `Driver` / `device_add` model in `crates/drivers/drv/src/model.rs`.

The real hardware bring-up mostly bypasses both as a true driver model. PCI enumeration in `crates/kernel/pci-boot` directly enables devices, maps BARs, configures virtqueues, installs global runtime state, and only then registers/binds model drivers as a sysfs-visible afterthought.

That must be corrected. The driver model should own matching, probing, binding, error unwind, remove, shutdown, sysfs state, devtmpfs publication, and uevents. The boot PCI path should enumerate devices and hand them to the driver core, not contain the drivers.

## Current architecture

### Driver core

At the earlier baseline, `crates/drivers/drv/src/lib.rs` exposed the legacy
probe system:

- `DriverEntry`
- `register(DriverEntry)`
- `probe_all(bdf)`

That path has since been removed from the live branch. It was a flat list of
probe functions and had no real device object, no binding state, no sysfs
lifecycle, no remove, no devtmpfs connection, and no useful bus semantics.

`crates/drivers/drv/src/model.rs` is the current model:

- `Device`
- `Driver`
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

`device_add()` now does the Linux-visible publication order:

1. reject duplicate `(bus, addr)` identities before publication
2. insert the device into the model registry
3. devtmpfs hook creates any `/dev` node
4. sysfs hook fires and emits the add uevent
5. attach an already-registered matching driver through the model

That fixes the earlier `/dev`-after-uevent race for model-owned devices.

The remaining problem is that some real devices still bypass authoritative
model binding and publication, so direct probe paths can still initialize
hardware before the model owns the lifecycle.

### Runtime state

Several drivers still use singleton global state:

- virtio-gpu: per-BDF installed device and scanout records; per-card DRM
  nodes, ioctl backend routing, runtime scanout hooks, scanout owner tokens,
  flip-event queues, dumb-buffer/FB object lookup, display-info/feature
  lookup, and per-fb owner-keyed fbdev flush/blank dispatch; dumb-buffer mmap
  lifetime is pinned through shared VMA backing and PMM object refs; fbcon has
  one explicit foreground console owner
- virtio-net modern: keyed device/runtime/name/stat/IPv4 ARP tables; exported
  TX/RX helper entry points require an owning device key; IPv6 NDP is
  stack-owned and keyed by interface in kernel builds; shared RX softirq/timer
  lifetime follows the last RX runtime; boot route/RS seeding iterates the
  registered virtio-net iface snapshot, but live multi-NIC proof is still
  missing
- virtio-rng: keyed records with one explicit active-BDF `/dev/hwrng`
  provider; promotion skips shutdown records instead of relying on vector order
- virtio-vsock: keyed transport records and owner-keyed protocol endpoint
  records; endpoint teardown and shutdown quiesce close only the matching
  owner's connections/backlog entries, RX protocol dispatch carries the
  transport owner key, quiesced endpoints are not advertised as live primary
  endpoints, AF_VSOCK bind/connect/listen/accept can select a specific live
  endpoint by local CID, listener socket close drops listener/backlog state,
  connected socket close removes the connection record, and duplicate owner or
  guest-CID publication is rejected
- virtio-snd: keyed transport records with EVENTQ drained per transport,
  owner-keyed EVENTQ counters/last-event snapshots, owner-keyed ops,
  owner-keyed ALSA card records, per-card
  `controlC<N>`/`pcmC<N>D0*` publication, and ALSA PCM/capture/OSS runtime
  state bound to the owning card key; live multi-card QEMU proof is still
  missing
- UART drivers: global `PRESENT` and base state; RX interrupt delivery now has
  an explicit quiesce gate cleared before shutdown/remove masks hardware
- PS/2 keyboard: global present/poll state; IRQ1 delivery now has an explicit
  quiesce gate cleared before shutdown/remove masks the controller line

Some subsystems are per-device already or closer to it:

- block registry stores multiple disks
- NVMe stores per-BDF controller records and publishes unique `nvmeXn1` disks
- AHCI stores per-BDF controller records and publishes unique `sdX` disks
- DRM core uses stable per-card backend slots and can keep multiple DRM
  backends registered in principle
- fbdev has a registry
- input has per-device event records, but some procfs metadata still needs
  broader live multi-device proof

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

### 2. There were two competing driver APIs

The legacy `DriverEntry/probe_all` path and the newer `Device/Driver` path
overlapped at the baseline. The flat API is now gone from live code on this
branch.

This creates ambiguity:

- Which API owns probing?
- Which API owns matching?
- Which API owns failure?
- Which API owns remove?
- Which API owns sysfs?

The old flat API has been removed. Remaining correctness work is in making all
live driver side effects obey the real model.

### 3. `probe()` is mostly a no-op

The `Driver` trait has `probe`, `remove`, and `shutdown`, but live model drivers often use default no-op `probe()` because the real work already happened in `pci-boot`.

This defeats the point of a driver model.

Every real hardware driver should move bring-up into `probe()` or into a bus-specific probe method called by `probe()`.

### 4. Binding error contract is now in the model

`bind()` is no longer just a string stamp. It validates the registered driver,
rejects already-bound and non-matching devices, calls `Driver::probe`, records
the binding only after probe succeeds, emits a model-backed `change` uevent, and
leaves the device unbound after probe failure.

Remaining work is not the bind contract itself; it is migrating every live
hardware bring-up path so the real side effects happen from model-owned probe
callbacks instead of enumeration-local direct calls.

### 5. Unbind/remove exists, but driver teardown proof is incomplete

The model has `/sys/bus/<bus>/drivers/<driver>/unbind`, model-level `unbind`,
`Driver::remove`, driver symlink/backref disappearance, devtmpfs node removal,
and `device_del` remove uevents. Driver-core tests assert the teardown order,
and sysfs/netlink tests prove bind/unbind `change` uevents plus `device_del`
`remove` uevents.

Still missing or needing broader proof:

- interrupt teardown
- DMA/free-page teardown
- BAR unmap
- sysfs child cleanup
- net/block/input/sound/DRM child unregister under real remove paths

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

- broader manual bind/unbind proof on real virtio devices
- broader device `driver` symlink correctness proof across hot rebind
- broader PCI resource/lifecycle proof beyond model-derived `resource*` attrs
- broader remove/change uevent behavior beyond driver-core ordering proof
- per-class child relationships

The issue is not that sysfs is synthesized. The issue is that the synthesized model does not yet expose Linux's required state transitions and links.

### 11. Device nodes must stay model-owned

Hardware-backed and real character/block device nodes now need to stay on the
`device_add`/class-device path. The remaining direct `devfs::register` users
are fixed pseudo-files, mountpoint underlay directories, devpts dynamic slave
entries, and coredump artifacts. Reintroducing driver-owned nodes through
direct devfs registration would make it hard to guarantee:

- correct `rdev`
- correct `/sys/dev/char`
- correct `/sys/dev/block`
- correct uevents
- correct teardown

The rule is: a device node belongs to a registered device object or a
registered class device object. Direct `devfs::register` is limited to fixed
pseudo-devices, non-device pseudo-files, and early boot namespace exceptions.

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

- remove `DriverEntry` / `probe_all` from the live path: done
- keep new probing on `Device` / `Driver` only: done for the live API
- add a real bind path that calls `probe`: done
- make `bind` return `Result`: done
- check already-bound state: done
- check driver exists: done
- check driver matches unless using explicit override: done
- bind only after successful probe: done
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
3. sound core per-card state for virtio-snd
4. virtio-vsock
5. UARTs
6. live proof for virtio-input, virtio-rng, NVMe, AHCI, and multi-device
   virtio-snd transport installs

Acceptance:

- two-device QEMU tests either expose both devices correctly or expose exactly one and leave the other unbound with a clear reason

### Phase 7: complete sysfs driver interfaces

Implement:

- `/sys/bus/<bus>/drivers/<driver>/bind`
- `/sys/bus/<bus>/drivers/<driver>/unbind`
- driver directory device symlinks to canonical `/sys/devices/...`
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

1. Remove direct probe/publication paths that still bypass model-owned binding.
2. Finish real remove-path proof for the single-device desktop stack: root disk,
   GPU/DRM/fbdev, input, sound, and net.
3. Prove the GNOME-visible coldplug path in QEMU/userspace: `/dev`, `/sys`,
   `/sys/dev`, class dirs, uevents, and udev seat state.
4. After the single-device path works, broaden fault injection and multi-device
   hardening.

## Do not do this

Do not keep adding sysfs illusions that claim a driver is bound if the model did not actually probe and bind it.

Do not fix multi-device bugs by silently ignoring second devices after partially initializing them.

Do not add userspace policy to the kernel to paper over missing driver/sysfs/uevent behavior.

Do not expand `pci-boot` into a larger pile of direct driver calls. It should shrink over time.

Do not publish `/dev` or `/sys` nodes before the owning driver/subsystem can service them.
