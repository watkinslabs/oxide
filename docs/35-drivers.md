# 35 Driver Model

DRAFT 2026-05-02. Dep:`01`,`02`,`16`,`18`,`19`,`22`,`34`. Provides:every driver crate.
## 1 Purpose

Driver registration, device matching, sysfs publication, hot-plug hooks. Devices come from buses (PCIe primary; virtio-mmio for some arm targets; platform via DT).

## 2 Invariants (frozen)

1. Each driver is a separate crate `drv-*`. Core kernel does not depend on any driver crate.
2. Drivers register via `linkme`-style static array (`distributed_slice!(DRIVERS)`); kernel iterates at boot and on hot-plug.
3. Every probed device has a `KObj` published at `/sys/devices/...` (per `19`).
4. Driver state owned by the driver instance the kernel hands out; no `static mut` per `06§11`.
5. `request_irq`/`free_irq` symmetric per probe/remove.
6. DMA buffers owned by the driver instance; lifetime ≤ device lifetime.

## 3 Public ifc

```rust
pub trait Driver: Send + Sync {
    fn name(&self) -> &'static str;
    fn matches(&self, dev: &Device) -> bool;
    fn probe(&self, dev: &Device) -> KR<Box<dyn DriverInstance>>;
}

pub trait DriverInstance: Send + Sync {
    fn remove(self: Box<Self>);
    fn shutdown(&self);                # called at system shutdown
}

pub enum Device { Pci(&PciDev), Virtio(&VirtioMmioDev), Platform(&PlatformDev) }
```

Distributed slice:
```rust
#[linkme::distributed_slice]
pub static DRIVERS: [&dyn Driver] = [..];
```

Kernel boot: iterate DRIVERS × discovered devices; first matching driver wins.

## 4 v1 driver list

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

Deferred to v1.x:
- `drv-igc`,`drv-ice` (Intel NIC), `drv-mlx5` (Mellanox).
- `drv-xhci` (USB host) + USB stack.
- `drv-hda` (Intel audio).

## 5 Driver lifecycle

1. Kernel enumerates devices (PCI walk, virtio-mmio scan, DT platform-device walk).
2. For each device: iterate `DRIVERS`, find first `matches()==true`.
3. Call `probe(&dev)`. On Ok, store the `Box<dyn DriverInstance>` in a per-device slot. On Err, log + try next driver.
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

v1 (no IOMMU): coherent uses uncached mapping (x86) / non-cacheable attr (arm). Streaming uses cacheable + explicit sync (`dma_wmb`/`dma_rmb` per `06§7`).

## 8 Test contract (frozen)

- All v1-mandatory drivers probe successfully under QEMU.
- `lspci` (busybox or our impl reading `/sys/bus/pci/`) shows expected devices.
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

## 12 Open Questions

- Driver hot-plug: PCI hot-plug deferred to v2; virtio-mmio hot-plug v1.x.
- `bind`/`unbind` from sysfs: defer to v1.x (writeable `/sys/bus/.../driver/{bind,unbind}`).
- Per-driver `MODULE_DEVICE_TABLE` autogen for udev/initramfs match: defer.
