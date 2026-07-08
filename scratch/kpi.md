Validate against this checklist.

```text
core module support
  ELF .ko loader
  relocation support
  symbol resolver
  EXPORT_SYMBOL / EXPORT_SYMBOL_GPL
  module_init / module_exit
  vermagic handling
  module parameters
  refcounting
  taint/state tracking

basic kernel APIs
  printk / pr_* logging
  BUG / WARN
  panic
  errno values
  container_of
  list_head
  hlist
  rbtree
  xarray / radix tree
  ida / idr
  bitmap helpers
  bitops
  atomic_t / refcount_t
  kref
  completion
  wait queues

memory allocation
  kmalloc / kzalloc / kcalloc
  kfree
  vmalloc / vfree
  alloc_pages / free_pages
  get_free_pages
  page structs
  GFP flags
  slab/cache allocator
  kstrdup / kasprintf
  memdup_user if supporting user paths

locking
  spinlock_t
  raw_spinlock_t
  mutex
  rwlock
  rwsem
  seqlock
  local_irq_save / restore
  preempt_disable / enable
  RCU basics
  lockdep stubs or real support

scheduler / async execution
  current task pointer
  task_struct basics
  schedule
  msleep / usleep_range / udelay / mdelay
  timers
  hrtimers
  workqueues
  delayed_work
  kthreads
  tasklets or compatibility stubs
  softirq bottom halves

interrupts
  request_irq
  free_irq
  enable_irq / disable_irq
  IRQ flags
  threaded IRQs
  MSI / MSI-X
  IRQ affinity
  interrupt context detection

MMIO / port I/O
  ioremap / iounmap
  readb/readw/readl/readq
  writeb/writew/writel/writeq
  memcpy_toio / memcpy_fromio
  inb/inw/inl
  outb/outw/outl
  memory barriers
  io barriers

DMA
  dma_alloc_coherent
  dma_free_coherent
  dma_map_single
  dma_unmap_single
  dma_map_page
  dma_unmap_page
  dma_map_sg
  dma_unmap_sg
  dma_sync_single_for_cpu
  dma_sync_single_for_device
  dma_set_mask_and_coherent
  scatterlist
  dma_addr_t
  IOMMU support or safe identity mapping

device model
  struct device
  struct driver
  struct bus_type
  struct class
  device_register / device_unregister
  driver_register / driver_unregister
  class_create / class_destroy
  device_create / device_destroy
  dev_* logging
  devm_* managed resources
  sysfs compatibility or stubs
  uevent / modalias support

PCI
  struct pci_dev
  struct pci_driver
  pci_register_driver
  pci_unregister_driver
  pci_enable_device
  pci_disable_device
  pci_request_regions
  pci_release_regions
  pci_resource_start
  pci_resource_len
  pci_iomap / pci_iounmap
  pci_set_master
  pci_set_drvdata / pci_get_drvdata
  pci_alloc_irq_vectors
  pci_free_irq_vectors
  pci_irq_vector
  PCI config read/write
  BAR enumeration
  MSI / MSI-X

USB
  struct usb_device
  struct usb_interface
  struct usb_driver
  usb_register
  usb_deregister
  endpoint descriptors
  control/bulk/interrupt transfers
  URBs
  DMA-safe USB buffers
  hotplug
  HID layer if using USB input devices

block layer
  struct block_device
  gendisk
  request_queue
  blk-mq
  bio
  request structs
  submit_bio
  blk_mq_alloc_tag_set
  blk_mq_init_queue
  add_disk / del_gendisk
  partition scanning
  flush / discard support

network stack
  struct net_device
  alloc_netdev / alloc_etherdev
  register_netdev
  unregister_netdev
  net_device_ops
  sk_buff
  napi
  netif_rx
  netif_start_queue / stop_queue / wake_queue
  ethtool_ops
  PHY / MDIO support
  checksum offload helpers
  packet allocator/free path

input
  input_dev
  input_allocate_device
  input_register_device
  input_unregister_device
  input_report_key
  input_report_abs
  input_sync
  evdev compatibility if exposing Linux input ABI

firmware loading
  request_firmware
  release_firmware
  firmware search path
  initramfs/user helper fallback

filesystem/sysfs/procfs
  sysfs enough for devices/drivers
  procfs enough for driver expectations
  debugfs stubs or implementation
  configfs if needed
  devtmpfs or device node creation

power management
  suspend/resume hooks
  runtime PM
  pm_runtime_get/put
  device power states
  PCI power management
  wakeup events

ACPI/platform
  ACPI table parsing
  ACPI device enumeration
  platform_device
  platform_driver
  platform_get_resource
  IRQ/resource translation
  device tree support if targeting ARM/RISC-V

char/misc devices
  cdev
  file_operations
  misc_register
  misc_deregister
  ioctl handling
  mmap file op support
  poll/select support

time/random/crypto helpers
  jiffies
  HZ
  ktime
  get_random_bytes
  crypto API if using WiFi/storage crypto
  CRC helpers
  hash helpers

userspace copy helpers
  copy_to_user
  copy_from_user
  get_user
  put_user
  access_ok

compat/version glue
  kernel version macros
  config macros
  generated autoconf.h-style values
  module license macros
  compiler attributes
  section annotations
```

Minimum useful target for simple PCI/storage/net drivers:

```text
module loader
kmalloc/kfree
spinlocks/mutexes
timers/workqueues
request_irq
ioremap/readl/writel
DMA mapping
struct device
PCI subsystem
block layer or netdev layer
firmware loader
```

Fast validation command against a Linux module:

```bash
nm -u driver.ko | sort -u
```

Every symbol listed there needs a compatible KPI implementation.

