# 35 Driver Model

FROZEN 2026-05-02. Dep:`01`,`02`,`16`,`18`,`19`,`22`,`34`. Provides:every driver crate.

## 1 Purpose

Driver registration, device matching, sysfs publication, hot-plug hooks. Devices come from buses (PCIe primary; virtio-mmio for some arm targets; platform via DT).

## 2 Invariants (frozen)

1. Each driver is a separate crate `drv-*`.
2. Drivers register `drv::Driver` objects at boot; bus enumeration calls `device_add()` and binds through `auto_bind()` / `bind()`.
3. Every probed device has a `KObj` published at `/sys/devices/...` (per `19`).
4. Driver state owned by the driver instance the kernel hands out; no `static mut` per `06§11`.
5. `request_irq`/`free_irq` symmetric per probe/remove.
6. DMA buffers owned by the driver instance; lifetime ≤ device lifetime.

## 3 Public ifc

```rust
pub trait Driver: Sync {
    fn bus(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn matches(&self, dev: &Device) -> bool;
    fn probe(&self, dev: &Arc<Device>) -> KResult<()>;
    fn remove(&self, dev: &Device);
    fn shutdown(&self, dev: &Device);
}

pub struct Device {
    pub bus: &'static str;
    pub addr: String;
    pub parent_bus: Option<&'static str>;
    pub parent_addr: Option<String>;
    pub vendor_id: u16;
    pub device_id: u16;
    pub class: u32;
    pub dev_class: &'static str;
    pub devname: Option<String>;
    pub dev_t: Option<(u32, u32)>;
}
```

Kernel boot: register drivers, enumerate buses, `device_add()` each device,
then bind the first matching driver whose `probe()` succeeds.

## 4 Driver list

Mandatory (must run):
- `drv-uart-16550` (x86 console)
- `drv-uart-pl011` (arm console)
- `drv-virtio-blk`
- `drv-virtio-net`
- `drv-virtio-rng`
- `drv-virtio-console` (alt console)
- `drv-virtio-vsock`
- `drv-virtio-input` (kbd/mouse)
- `drv-virtio-gpu` (framebuffer)
- `drv-nvme`
- `drv-ahci`
- `drv-ps2-keyboard` (x86 only; legacy fallback)
- `drv-simplefb` (firmware linear-framebuffer fallback after native display probe)

Tracked as later phases:
- `drv-igc`,`drv-ice` (Intel NIC), `drv-mlx5` (Mellanox).
- `drv-xhci` (USB host) + USB stack (phase 34).
- `drv-hda` (Intel audio).

## 5 Driver lifecycle

1. Kernel enumerates devices (PCI walk, virtio-mmio scan, DT platform-device walk).
2. For each device: call `device_add()` so devtmpfs/sysfs publication happens in one ordered path.
3. Bind through `auto_bind()` / `bind()`. `Driver::probe()` must fully bring up the device or unwind all partial state before returning an error.
4. Probe sets up: BAR map, IRQ register, sysfs attributes, devfs node (if char/block device), register with subsystem (`register_netdev`,`register_block_device`,`tty_register`).
5. Shutdown: call `shutdown()`; then `remove()` to free.

## 6 Concurrency

Per-driver-instance: implementation-defined locks. Subsystem callbacks (e.g., `NetDev::xmit`) may be called concurrently; driver must handle.

Probe runs single-threaded per device; post-probe is concurrent.

## 7 DMA

```rust
pub struct DmaBuf { pa: PhysAddr, va: NonNull<u8>, len: usize, /* refcount, owner */ }
pub fn dma_alloc_coherent(len: usize) -> KR<DmaBuf>;
pub fn dma_alloc_streaming(len: usize, dir: DmaDir) -> KR<DmaBuf>;
pub fn dma_sync_for_device(buf: &DmaBuf);
pub fn dma_sync_for_cpu(buf: &DmaBuf);
```

No IOMMU yet: coherent uses uncached mapping (x86) / non-cacheable attr (arm). Streaming uses cacheable + explicit sync (`dma_wmb`/`dma_rmb` per `06§7`).

## 8 Test contract (frozen)

- All mandatory drivers probe successfully under QEMU.
- `lspci` (reading `/sys/bus/pci/`) shows expected devices.
- virtio-blk: read+write 1 GiB; verify SHA-256.
- virtio-net: ping loopback through L3.
- nvme: read+write 1 GiB to a QEMU-emulated NVMe controller.
- `shutdown()` of every probed driver runs cleanly (verify by inspecting sysfs counts before/after).
- Coverage ≥75% per driver crate.

## 9 Failure modes

- Probe failure: log error; device left unbound; kernel continues.
- IRQ not available: probe returns error.
- DMA buffer too large for non-IOMMU bounce: probe limits accepted I/O size.

## 10 Debug

`debug-driver`: per-driver verbose probe trace; sysfs attribute access logging.

## 11 Cross-spec

`16`/`19` (devfs/sysfs publishing), `22` (IRQ + DMA barriers), `25` (NetDev), `17` (BlockDevice), `28` (Tty), `34` (PCI).

## 12 Backlight class

Panel brightness control. Brightness keys and a desktop's slider act on this
tree.

Ownership: `crates/kernel/backlight` owns the class (registered devices, the
brightness and power rules, the attribute contract).
`crates/kernel/sysfs` projects it at `/sys/class/backlight/<name>/`.

### 12.1 Invariants (frozen)

1. Attributes: `bl_power` and `brightness` read-write, `actual_brightness`,
   `max_brightness`, `scale` and `type` read-only.
2. A brightness write above `max_brightness` is refused with `EINVAL`. The
   class does not clamp: a clamped write is indistinguishable from an honoured
   one.
3. A write to a device whose driver has gone reports `ENXIO` and never reaches
   the driver.
4. A blanked device programs zero without losing the requested level. Blank is
   `bl_power != 0` or either `state` bit set.
5. `actual_brightness` prefers the driver readback; a driver with none reports
   the requested level.
6. An unchanged `bl_power` write does not call the driver; a failed change is
   rolled back.
7. A brightness write always produces a change notification, including one the
   driver refused.
8. Registration refuses a duplicate name (`EEXIST`) and coerces an
   out-of-range type to `raw`.

### 12.2 ACPI video provider

`crates/kernel/firmware` publishes panels that declare a brightness-level list
(`_BCL`), driving them through `_BCM` and reading back through `_BQC` after
taking brightness ownership with `_DOS`. The firmware list is normalised once
into a dense `0..max` index: repeats are dropped, a list that omits its
mains/battery entries gains them back, and a descending list is sorted so a
higher index is brighter. Whether `_BQC` returns a level or an index is
settled at registration by programming a known level and reading it back.

### 12.3 Test contract (frozen)

- Range validation, the blank rules, the power rollback and the attribute
  bodies are hosted tests over ungated modules.
- `_BCL` normalisation and `_BQC` classification are hosted tests over the
  raw package.

## 13 Thermal class

Thermal zones and the cooling devices bound to them. A laptop that never reads
its sensors runs at a fixed operating point until the hardware protects itself,
which is the last mechanism anyone wants relied on.

Ownership: `crates/kernel/thermal` owns the class — the trip ladder with its
hysteresis, the governors, the binding, the polling cadence and the attribute
contract. `crates/kernel/sysfs` projects it at `/sys/class/thermal/`.
`crates/kernel/firmware` owns the ACPI provider. The terminal action for a
critical trip is installed by kernel init from `crates/kernel/power`, because
powering the machine down is not a device class's decision to own (`32§16`).

### 13.1 Units (frozen)

| Field | Unit |
|---|---|
| every temperature and hysteresis | millidegrees Celsius |
| polling cadences | milliseconds |
| `time_in_state_ms` | milliseconds |

Firmware reports tenths of a kelvin and tenths of a second; both convert at
the provider boundary.

### 13.2 Invariants (frozen)

1. Zones and cooling devices share one class directory, distinguished by name
   prefix. Both are named by the class, never by a provider.
2. A trip is crossed upward at its temperature inclusive, and downward only
   once the temperature is strictly below the whole hysteresis band. The
   crossing state, not a re-comparison against the trip temperature, is what
   the next reading is classified against.
3. A trip crossing is reported once per crossing. A trip already reached does
   not re-fire.
4. Trip indexes are contiguous and stable: a level the provider did not
   declare is left out, not held as a placeholder, and the declaration order
   is fixed so a later boot does not rename every attribute.
5. A cooling device shared between zones is driven to the deepest state any
   of them asks for. A write to `cur_state` is a request aggregated with the
   rest, not a command that undercuts an active trip.
6. A binding is refused where the device cannot satisfy the requested range,
   rather than clamped. A device whose range later shrinks pulls the binding
   and any live request down with it; one bound to the whole device follows it
   upward.
7. A zone polls at its passive cadence while any passive trip is engaged, and
   at its ordinary one otherwise.
8. A sensor that reports "not ready" is retried at a fixed cadence forever. A
   sensor that fails is backed off and, once the backoff passes two minutes,
   the zone is disabled rather than polled for the life of the machine.
9. The terminal trip powers the machine off. The hot trip notifies and does
   not.
10. A governor never drives a terminal trip.

### 13.3 Governors

`step_wise` moves each device one state per sample in the direction the
temperature is going, and while a trip is still throttling it may not release
its device entirely. `bang_bang` is on above the trip and off below the band.
`fair_share` divides the work by weight across the devices bound to a zone.
`user_space` publishes each crossing and cools nothing. `step_wise` is the
default: it works with a device of any depth, where the two-valued governor
would drive a multi-state device to its shallowest useful state.

### 13.4 ACPI provider

`crates/kernel/firmware` publishes the firmware-described zones: `_TMP` for
the reading, `_CRT`/`_HOT`/`_PSV`/`_ACx` for the ladder, `_TZP`/`_TSP` for the
cadences, `_SCP` to ask the platform to react rather than throttle, and
`_PSL`/`_ALx` for the devices each trip may drive. The kelvin offset firmware
used is inferred from the critical trip. A zone whose ladder has no usable
trip is not published: a zone that can never act is a temperature readout, and
publishing it as a zone tells a daemon the machine is protected when it is not.

### 13.5 Test contract (frozen)

- Crossing detection with its hysteresis, the interrupt window, cadence
  selection, the sensor-failure backoff, every governor's decision, binding
  and range reconciliation, aggregation across zones, and every attribute's
  rendering are hosted tests over ungated modules.
- A millidegree reported as a degree, and a nanosecond occupancy reported
  unconverted, each fail a named test.
- The firmware conversion is covered from both kelvin offsets, and a reading
  outside what a sensor can report is refused.
