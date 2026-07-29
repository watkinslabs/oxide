# 34 PCI/PCIe

FROZEN 2026-05-02. Dep:`01`,`02`,`11`,`19`,`22`,`33`,`35`. Provides:every PCIe device driver.

## Revision 2026-07-29 (R01)

- Changed: MSI-X remains preferred when a driver benefits from independent vectors; single-vector devices may use MSI, and INTx remains the final fallback. This matches Linux `pci_alloc_irq_vectors()` selection and lets AHCI use the ICH9 controller's MSI capability instead of requiring a nonexistent MSI-X table.

## 1 Purpose

Enumerate PCIe devices via ECAM. Allocate BARs (or read pre-assigned). Configure MSI-X/MSI with INTx fallback. Expose `/sys/bus/pci/devices/`. No legacy 0xCF8/0xCFC config-cycle access.

## 2 Invariants (frozen)

1. Only ECAM access (PCIe). Per `03§7`.
2. Prefer MSI-X when independent vectors improve the driver; use MSI for single-vector devices or when MSI-X is absent; use INTx only when neither message-signalled mode is usable.
3. BARs respected at boot if firmware (UEFI) assigned them; never reassigned.
4. IOMMU: pass-through (no protection). Intel VT-d / arm SMMU isolation tracked as later phase.

## 3 Public ifc

```rust
pub struct PciDev { pub bdf:Bdf, pub vid:u16, pub did:u16, pub class:u32, pub bars:[Bar;6], pub caps:Vec<PciCap> }
pub fn pci_enumerate(bridges:&[PciHostBridge]) -> &'static [PciDev];

pub fn pci_bar_map(dev:&PciDev, idx:u8) -> KR<NonNull<u8>>;     // mmio map
pub fn pci_msix_alloc(dev:&PciDev, count:u8, handler:fn(u32)) -> KR<Vec<MsiHandle>>;
pub fn pci_msi_alloc(dev:&PciDev, handler:fn(u32)) -> KR<MsiHandle>;
pub fn pci_set_master(dev:&PciDev);                              # bus master enable
pub fn pci_cfg_read(dev:&PciDev, off:u16, sz:u8) -> u32;
pub fn pci_cfg_write(dev:&PciDev, off:u16, val:u32, sz:u8);
```

## 4 Enumeration

For each bridge in `pci_host_bridges()`:
- Walk bus 0 .. bridge.bus_end.
- For each bus, dev 0..32, fn 0..8: read VID/DID; if 0xFFFF, skip.
- Read header type; if 0x80 (multi-fn), iterate functions; else only fn 0.
- Read class, BARs, capability list.
- For PCI-PCI bridges: recurse into secondary bus.
- Build `PciDev` records. Publish to `/sys/bus/pci/devices/`.

## 5 BAR map

Each BAR: 32-bit or 64-bit, mem or I/O, prefetch flag. Decoded from BAR register. Mapped via VMM `vmalloc`-like into kernel space with attributes per type (UC for MMIO, WC for prefetchable).

I/O BARs (x86 only): not mapped; accessed via `inb`/`outb`. Discouraged; current drivers shouldn't need.

## 6 MSI/MSI-X

Allocate vectors via IrqOps (`alloc_msi`) and program addr/data per arch (APIC: addr=`0xFEE0_0000 | dest`, data=`vector`; GICv3: ITS-mediated).

MSI-X capability points at table BAR + offset. Program each table entry while masked, install its handler, then enable MSI-X and clear the function mask.

MSI capability carries its message address/data in config space. Program it disabled, install the handler, then set MSI Enable. Single-vector devices use MME=0.

## 7 Capabilities walked

| Cap | Use |
|---|---|
| MSI | single-vector interrupt routing or MSI-X absence |
| MSI-X | preferred independent-vector routing |
| PM | power state (D0 only) |
| PCIe (cap 0x10) | link speed, max payload |
| AER | error reporting (later phase) |
| ATS / PRI | IOMMU advanced (later phase) |
| SR-IOV | virtualization (later phase) |

## 8 IOMMU

Now: identity-map all DMA (passthrough). DMA targets must be physical addresses our PMM allocated.
Later phase: enable Intel VT-d / SMMU. Per-device DMA domains. `dma_map_*` API.

## 9 Concurrency

Enumeration single-threaded at boot. Post-boot config writes serialized per-bridge spinlock.

## 10 Perf budget

| Op | p99 |
|---|---|
| `pci_cfg_read` | ≤ 200 cy (ECAM is cached) |
| MSI-X program 1 vec | ≤ 1 µs |

## 11 Test contract (frozen)

- QEMU q35 with `-device virtio-blk-pci,...,-device virtio-net-pci,...,-device nvme,...`: enumeration finds all; class IDs match.
- BAR map: read VID/DID via cfg vs MMIO offset 0; agree.
- MSI/MSI-X alloc: each vector fires correctly when device generates int.
- `/sys/bus/pci/devices/<bdf>/{vendor,device,class,resource}` populated.
- Coverage ≥85%.

## 12 Failure modes

- BAR overlap with another device (firmware bug): kassert with offending pair.
- MSI-X table outside BAR range: try MSI, then INTx.
- MSI message allocation/programming failure: fall back INTx.

## 13 Debug

`debug-pci`: per-device cfg-space dump; cap walk trace.

## 14 Cross-spec

`33` (MCFG/DT for ECAM regions), `22` (IRQ alloc/route), `19` (`/sys/bus/pci/`), `35` (driver match by VID/DID).
