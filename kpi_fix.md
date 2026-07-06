# KPI Fix Ledger

Date: 2026-07-06

Scope: `kpi.md` is a Kernel Porting Interface checklist for loading Linux-style
drivers/modules. Status below is based on code inspection, not on checklist text.
Branch names marked `TBD-*` are ordered slugs; claim the actual next counter from
`metadata/index.md` immediately before starting each row.

## Current Truth

Have: Rust-native driver model, PCI config/BAR/MSI primitives, devtmpfs/sysfs/procfs
device views, char/block dev_t dispatch, PMM buddy allocator, slab cache, spin/rw
locks, RCU, wait queues, timer registry, softirq slots, netdev/block traits, ACPI
table parsing, user-buffer validation, x86_64 ET_REL loader prototype, and symbol
table/export registry.

Do not have: a Linux C module ABI, real `init_module`/`finit_module`/`delete_module`
lifecycle, `.modinfo`/vermagic/module parameter parsing, a Linux header/shim layer,
generic `request_irq`, generic DMA mapping API, generic MMIO/port-I/O API, devm
resources, mature Linux PCI/block/net/input/USB APIs, firmware loader, power/runtime
PM, config/autoconf/version glue, or nm-based validation against real `.ko` files.

## Buildout Order

| Status | Priority | Branch | Description |
| --- | --- | --- | --- |
| DONE | P0 | existing | PMM/slab primitives exist as Rust APIs: buddy allocator, page metadata, slab cache, and `kalloc`/`vmalloc`-style shared allocator code. Still not exposed as Linux `kmalloc/kzalloc/kcalloc/kfree/vmalloc/vfree` KPI symbols. |
| DONE | P0 | existing | Core synchronization exists as Rust APIs: `Spinlock`, `RwLock`, RCU basics, wait queues, IRQ-save lock gate, and softirq slots. Still not exposed as Linux `spinlock_t`, `mutex`, `completion`, `work_struct`, or `wait_queue_head_t` ABI shims. |
| DONE | P0 | existing | Rust driver model exists: `drv::Device`, `drv::Driver`, device add/remove, driver bind/unbind, devtmpfs/sysfs hooks, uevents/modalias/devname/dev_t. Not Linux `struct device`, `struct driver`, `bus_type`, `class`, `devm_*`. |
| PARTIAL | P0 | existing | Module infrastructure exists: x86_64 ET_REL parser/loader, relocation engine, symbol table with GPL gating, and kernel export registry. Missing executable mapping, module init/exit call path, unload safety, `.modinfo`, vermagic, parameters, taint/state, aarch64 relocations. |
| PARTIAL | P0 | existing | PCI primitives exist: config reader trait, BDF parsing, BAR decoding/resources, command register helpers, capability/MSI-X helpers, and PCI-backed driver registration through `drv`. Missing Linux `struct pci_dev`, `pci_driver`, `pci_register_driver`, region ownership, `pci_iomap`, IRQ-vector wrappers, drvdata helpers. |
| PARTIAL | P0 | existing | IRQ/MSI support exists for internal drivers: x86 MSI vector allocator/handler table, aarch64 fixed INTID handlers, GICv2m state. Missing generic Linux `request_irq/free_irq`, IRQ flags, threaded IRQs, affinity, enable/disable API. |
| PARTIAL | P0 | existing | Block/net internals exist: `BlockDevice`, `PageCache`, disk registry, `NetDev`, netdev registry, stats, virtio-net/blk drivers. Missing Linux `gendisk`, `request_queue`, blk-mq, bio/request APIs, `struct net_device`, `net_device_ops`, skb/NAPI compatibility wrappers. |
| PARTIAL | P0 | existing | Filesystem compatibility exists for sysfs/procfs/devtmpfs/tracefs and VFS special nodes. Missing debugfs/configfs compatibility layer and Linux kobject/kset/sysfs helper API surface used by out-of-tree drivers. |
| VERIFIED | P0 | F650-kpi-symbol-audit | Built `tools/kpi-audit`: ingests `.ko` files through `nm -u` or captured nm output, scans implemented module exports, classifies unresolved symbols by KPI area, emits a ledger-ready missing-symbol table, and can fail a gate with `--fail-on-missing`. |
| VERIFIED | P0 | F651-kpi-uapi-header-surface | Added `kpi/include` Linux-shaped module header surface: generated config/release headers, compiler attributes/types, section annotations, module license/init/exit/export macros, errno/types, `container_of`, list/hlist/rbtree/xarray/idr/bitmap/bitops declarations, plus x86_64/aarch64 `-nostdinc` compile smoke. |
| PARTIAL | P0 | F652-kpi-module-loader-lifecycle | Advanced module lifecycle: registry now tracks stable names, state, size, refcount fields, tombstoned slots, name-based unload, and `/proc/modules` uses the lifecycle snapshot; `delete_module(name)` now reads the Linux user string instead of treating the pointer as an index. Remaining: executable/W^X module memory, `module_init`/`module_exit` calls, full refcount users, taint flags, async drain. |
| GAP | P0 | TBD-F-kpi-modinfo-vermagic-params | Parse `.modinfo`: name, license, author, description, depends, vermagic, parm entries. Enforce license/GPL symbol rules, reject incompatible vermagic, and expose module parameters/state through procfs or sysfs-compatible files. |
| GAP | P0 | TBD-F-kpi-aarch64-module-relocs | Add aarch64 ET_REL relocation support and tests so module loading is lockstep across x86_64 and aarch64. Required before any KPI item can be considered complete. |
| GAP | P1 | TBD-F-kpi-linux-alloc-api | Export Linux allocation API wrappers over existing allocators: `kmalloc`, `kzalloc`, `kcalloc`, `kfree`, `vmalloc`, `vfree`, `alloc_pages`, `free_pages`, `get_free_pages`, `kstrdup`, `kasprintf`, GFP flag parsing, `struct page` accessors. |
| GAP | P1 | TBD-F-kpi-linux-sync-api | Export Linux synchronization wrappers: `spinlock_t`, `raw_spinlock_t`, `mutex`, `rwlock_t`, `rw_semaphore`, `seqlock_t`, `completion`, `wait_queue_head_t`, `atomic_t`, `refcount_t`, `kref`, lockdep-compatible stubs. |
| GAP | P1 | TBD-F-kpi-time-workqueues | Build Linux timer/async API on existing scheduler/timer/softirq pieces: `jiffies`, `HZ`, `ktime`, `msleep`, `usleep_range`, `udelay`, `mdelay`, `timer_list`, `hrtimer`, workqueues, delayed_work, kthreads, tasklet compatibility. |
| GAP | P1 | TBD-F-kpi-mmio-portio-api | Add generic MMIO/port-I/O facade: `ioremap`, `iounmap`, `readb/readw/readl/readq`, `writeb/writew/writel/writeq`, `memcpy_toio`, `memcpy_fromio`, x86 `inb/inw/inl/outb/outw/outl`, memory and I/O barriers. |
| GAP | P1 | TBD-F-kpi-dma-api | Add DMA mapping API: coherent allocation/free, streaming map/unmap single/page/sg, sync for CPU/device, mask negotiation, scatterlist type, `dma_addr_t`, and explicit identity/IOMMU policy for both arches. |
| GAP | P1 | TBD-F-kpi-irq-api | Wrap internal IRQ plumbing in Linux-shaped APIs: `request_irq`, `free_irq`, `enable_irq`, `disable_irq`, flags, IRQ context detection, threaded IRQ worker path, MSI/MSI-X helpers, affinity stubs or implementation. |
| GAP | P2 | TBD-F-kpi-device-core-api | Provide Linux device core facade: `struct device`, `struct driver`, `struct bus_type`, `struct class`, register/unregister/create/destroy helpers, `dev_*` logging, `dev_set/get_drvdata`, `devm_*` managed resources, sysfs attrs, uevents/modalias integration. |
| GAP | P2 | TBD-F-kpi-pci-api | Build Linux PCI driver facade over existing PCI/drv code: `struct pci_dev`, `struct pci_driver`, register/unregister, enable/disable, request/release regions, resource helpers, `pci_iomap`, bus mastering, drvdata, IRQ-vector allocation/free/vector lookup, config read/write. |
| GAP | P2 | TBD-F-kpi-char-misc-api | Add Linux char/misc API wrappers: `cdev`, `file_operations`, `misc_register`, `misc_deregister`, ioctl/mmap/poll bridging to VFS `FileOps`, and lifetime/refcount rules. |
| GAP | P2 | TBD-F-kpi-firmware-loader | Implement `request_firmware`/`release_firmware`, firmware search path, initramfs-backed lookup, and optional userspace-helper decision. Several storage/net/WiFi drivers will block here. |
| GAP | P3 | TBD-F-kpi-netdev-api | Add Linux netdev compatibility: `struct net_device`, `alloc_netdev/alloc_etherdev`, `register_netdev`, `net_device_ops`, skb allocator/free path, `netif_rx`, queue start/stop/wake, ethtool_ops, checksum helpers, PHY/MDIO stubs or implementation. |
| GAP | P3 | TBD-F-kpi-block-api | Add Linux block compatibility: `block_device`, `gendisk`, request_queue, blk-mq tag set/init queue, bio/request structures, submit_bio, add_disk/del_gendisk, partition scan, flush/discard support. |
| GAP | P3 | TBD-F-kpi-input-api | Add Linux input compatibility over existing virtio-input/evdev: `input_dev`, allocate/register/unregister, report key/abs/sync helpers, capability bitmaps, LED/status path, evdev ABI parity checks. |
| GAP | P3 | TBD-F-kpi-usb-api | Add USB core only if target drivers need it: device/interface/driver structs, register/deregister, descriptors, control/bulk/interrupt transfers, URBs, DMA-safe buffers, hotplug, HID layer for USB input. |
| GAP | P3 | TBD-F-kpi-platform-acpi-dt | Add platform/ACPI/DT driver facade: `platform_device`, `platform_driver`, resource lookup, IRQ/resource translation, ACPI device enumeration, device-tree support for ARM targets. |
| GAP | P4 | TBD-F-kpi-power-pm | Add power-management compatibility: suspend/resume hooks, runtime PM get/put, device power states, PCI PM, wakeup events. |
| GAP | P4 | TBD-F-kpi-crypto-random-crc | Export helper APIs commonly needed by drivers: `get_random_bytes`, CRC helpers, hash helpers, and crypto API stubs or real implementation based on target driver demand. |
| GAP | P4 | TBD-F-kpi-usercopy-api | Consolidate current syscall-only user-buffer validation into exported driver-safe `access_ok`, `copy_to_user`, `copy_from_user`, `get_user`, `put_user` helpers with fault-safe behavior or explicit non-sleeping limits. |
| GAP | P4 | TBD-F-kpi-debugfs-configfs | Add debugfs stubs/implementation and configfs if the chosen driver set references them. Keep as late as possible unless `kpi-audit` shows early demand. |

## Minimum Useful Path

1. Build `kpi-audit` and choose 2-3 real target `.ko` files.
2. Finish module loader lifecycle and both-arch relocations.
3. Add header/macro compatibility so target drivers compile unchanged or with minimal config.
4. Export alloc/sync/time/MMIO/DMA/IRQ APIs.
5. Add device core + PCI facade.
6. Only then build block/net/input-specific facades, ordered by unresolved symbols from real drivers.
