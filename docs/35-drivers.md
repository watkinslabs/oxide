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
