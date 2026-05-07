// Legacy virtio-net (`vendor=0x1AF4`, `device=0x1000`) driver per
// Virtio 1.2 §4.1.4 (legacy interface). Modern virtio-net (device
// 0x1041) requires PCI capability list walking + BAR mapping + MMIO
// notify regions, deferred. The legacy interface uses port-I/O
// against BAR0 for everything, which is straight-line code and is
// what QEMU defaults to with `-device virtio-net-pci,disable-modern=on`
// or older Q35/i440FX templates.
//
// Init sequence (V1.2 §3.1.1):
//   1. Reset:          STATUS = 0
//   2. Ack:            STATUS |= ACK
//   3. Driver:         STATUS |= DRIVER
//   4. Negotiate:      read DEVICE_FEATURES, write DRIVER_FEATURES (subset)
//   5. (modern only)   STATUS |= FEATURES_OK; verify
//   6. Setup queues:   for q in [RX,TX]: select, read size, alloc PFN, write
//   7. Driver-OK:      STATUS |= DRIVER_OK
//   8. Fill RX ring with descriptors pointing at receive buffers
//
// This module does steps 1-7. Frame TX/RX (step 8 + the post-init
// data path) lands in a follow-up phase 19 PR.

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
#![allow(dead_code)]

use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

const VIRTIO_VENDOR:               u16 = 0x1AF4;
const VIRTIO_DEVICE_NET_LEGACY:    u16 = 0x1000;
const VIRTIO_DEVICE_NET_MODERN:    u16 = 0x1041;

// Device status bits (legacy + modern share the encoding).
const STATUS_RESET:       u8 = 0x00;
const STATUS_ACK:         u8 = 0x01;
const STATUS_DRIVER:      u8 = 0x02;
const STATUS_DRIVER_OK:   u8 = 0x04;
const STATUS_FEATURES_OK: u8 = 0x08;
const STATUS_FAILED:      u8 = 0x80;

// Legacy I/O port offsets within BAR0.
const VIO_DEVICE_FEATURES: u16 = 0x00;
const VIO_DRIVER_FEATURES: u16 = 0x04;
const VIO_QUEUE_PFN:       u16 = 0x08;
const VIO_QUEUE_SIZE:      u16 = 0x0C;
const VIO_QUEUE_SEL:       u16 = 0x0E;
const VIO_QUEUE_NOTIFY:    u16 = 0x10;
const VIO_DEVICE_STATUS:   u16 = 0x12;
const VIO_ISR_STATUS:      u16 = 0x13;
const VIO_NET_MAC:         u16 = 0x14;
const VIO_NET_STATUS:      u16 = 0x1A;

// Net feature bits (subset honored).
const VIRTIO_NET_F_MAC:    u32 = 1 << 5;
const VIRTIO_NET_F_STATUS: u32 = 1 << 16;

const QUEUE_RX: u16 = 0;
const QUEUE_TX: u16 = 1;

const PAGE_SIZE: u64 = 4096;
const HHDM_FALLBACK: u64 = 0xFFFF_8000_0000_0000; // matches user_as::hhdm_offset() default

/// One installed virtio-net device's runtime state.
pub struct VirtioNetDevice {
    pub iobase: u16,
    pub mac:    [u8; 6],
    pub rx:     VirtQueueRuntime,
    pub tx:     VirtQueueRuntime,
}

/// Per-queue runtime (descriptor / avail / used ring physical layout).
/// All three structures live in a single page-aligned PMM allocation
/// so the device sees them at one PFN. Sizes computed from queue size
/// per Virtio 1.2 §2.6.
pub struct VirtQueueRuntime {
    pub size:        u16,
    pub region_pa:   u64,
    pub region_va:   u64,
    pub region_len:  usize,
    pub next_avail:  u16,
    pub last_used:   u16,
}

static DEVICE: Spinlock<Option<VirtioNetDevice>, DriverLockClass> =
    Spinlock::new(None);

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Returns true if a virtio-net device is present + initialized.
/// # C: O(1)
pub fn is_present() -> bool { INITIALIZED.load(Ordering::Acquire) }

// -------- port I/O helpers --------

/// # SAFETY: caller asserts `port` is owned by this driver (BAR0
/// of an initialized virtio-net device); port-I/O has well-defined
/// hardware behavior on x86; no memory operands.
/// # C: O(1)
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: port-I/O; well-defined on x86; no memory side-effects beyond device.
    unsafe {
        asm!("out dx, al",
             in("dx") port, in("al") val,
             options(nomem, nostack, preserves_flags));
    }
}

/// # SAFETY: same as outb.
/// # C: O(1)
unsafe fn outw(port: u16, val: u16) {
    // SAFETY: port-I/O; well-defined on x86; no memory side-effects beyond device.
    unsafe {
        asm!("out dx, ax",
             in("dx") port, in("ax") val,
             options(nomem, nostack, preserves_flags));
    }
}

/// # SAFETY: same as outb.
/// # C: O(1)
unsafe fn outl(port: u16, val: u32) {
    // SAFETY: port-I/O; well-defined on x86; no memory side-effects beyond device.
    unsafe {
        asm!("out dx, eax",
             in("dx") port, in("eax") val,
             options(nomem, nostack, preserves_flags));
    }
}

/// # SAFETY: same as outb; reads only.
/// # C: O(1)
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: port-I/O read; reads only from the device.
    unsafe {
        asm!("in al, dx",
             out("al") v, in("dx") port,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// # SAFETY: same as inb.
/// # C: O(1)
unsafe fn inw(port: u16) -> u16 {
    let v: u16;
    // SAFETY: port-I/O read; reads only from the device.
    unsafe {
        asm!("in ax, dx",
             out("ax") v, in("dx") port,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// # SAFETY: same as inb.
/// # C: O(1)
unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    // SAFETY: port-I/O read; reads only from the device.
    unsafe {
        asm!("in eax, dx",
             out("eax") v, in("dx") port,
             options(nomem, nostack, preserves_flags));
    }
    v
}

// -------- BAR + queue setup --------

fn read_bar0_iobase<R: pci::ConfigSpaceReader>(r: &R, bdf: pci::Bdf) -> Option<u16> {
    let bar0 = r.read32(bdf, 0x10);
    if (bar0 & 0x1) == 0 { return None; } // memory BAR — not legacy virtio
    let iobase = (bar0 & !0x3) as u16;
    if iobase == 0 { return None; }
    Some(iobase)
}

/// Allocate a virtqueue ring: descriptor table (16B × size) + avail
/// ring (6 + 2×size) padded to 4-byte boundary, then used ring (6 +
/// 8×size). All in one contiguous page-aligned region so the device
/// sees a single PFN. v1 caps queue size at 64 — keeps the region
/// well within a single 4 KiB page.
fn alloc_queue_region(size: u16) -> Option<VirtQueueRuntime> {
    let size_u64 = size as u64;
    let desc_bytes  = 16 * size_u64;
    let avail_bytes = 6 + 2 * size_u64;
    let used_off    = (desc_bytes + avail_bytes + 3) & !3u64;
    let used_bytes  = 6 + 8 * size_u64;
    let total       = used_off + used_bytes;
    if total > PAGE_SIZE { return None; }

    let pa = crate::pmm_setup::alloc_one_frame()?;
    let va = pa + crate::user_as::hhdm_offset();
    // SAFETY: HHDM-mapped page; zero a single 4KiB region we just allocated.
    unsafe { core::ptr::write_bytes(va as *mut u8, 0, PAGE_SIZE as usize); }
    Some(VirtQueueRuntime {
        size,
        region_pa: pa,
        region_va: va,
        region_len: PAGE_SIZE as usize,
        next_avail: 0,
        last_used: 0,
    })
}

/// Configure one queue on the device: select it, read the size the
/// device suggests, allocate a region, and write the PFN.
/// # SAFETY: caller asserts `iobase` is the legacy-virtio port range
/// for this device and we hold exclusive access (single-mutator UP).
unsafe fn setup_queue(iobase: u16, qid: u16) -> Option<VirtQueueRuntime> {
    // SAFETY: writing to virtio queue-select; well-defined per spec.
    unsafe { outw(iobase + VIO_QUEUE_SEL, qid); }
    // SAFETY: device tells us the queue size.
    let dev_size = unsafe { inw(iobase + VIO_QUEUE_SIZE) };
    if dev_size == 0 { return None; }
    let size = core::cmp::min(dev_size, 64);
    let q = alloc_queue_region(size)?;
    let pfn = (q.region_pa / PAGE_SIZE) as u32;
    // SAFETY: PFN write commits the queue to the device.
    unsafe { outl(iobase + VIO_QUEUE_PFN, pfn); }
    Some(q)
}

// -------- discover + init --------

/// Boot-time entry point. Walks PCI for the first virtio-net device,
/// runs the legacy init handshake, allocates RX + TX queue regions,
/// stashes the result in DEVICE.
///
/// # SAFETY: boot-path single-CPU; PMM up; HHDM mapped. After this
/// returns, `is_present()` indicates whether a device was found and
/// initialized.
/// # C: O(devices)
pub fn init_legacy() {
    if INITIALIZED.load(Ordering::Acquire) { return; }
    let r = hal_x86_64::pci::LegacyPci;
    let devs = pci::enumerate(&r);

    let mut chosen: Option<pci::PciDevice> = None;
    for d in devs.iter() {
        if d.vendor_id == VIRTIO_VENDOR && d.device_id == VIRTIO_DEVICE_NET_LEGACY {
            chosen = Some(*d);
            break;
        }
    }
    let dev = match chosen { Some(d) => d, None => return };

    let iobase = match read_bar0_iobase(&r, dev.bdf) { Some(b) => b, None => return };

    // -- Init handshake --
    // SAFETY: legacy virtio; iobase came from BAR0; well-defined I/O.
    unsafe {
        outb(iobase + VIO_DEVICE_STATUS, STATUS_RESET);
        outb(iobase + VIO_DEVICE_STATUS, STATUS_ACK);
        outb(iobase + VIO_DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER);
    }
    // Feature negotiation: accept the subset we honor.
    // SAFETY: read/write per legacy virtio config layout.
    let dev_feat = unsafe { inl(iobase + VIO_DEVICE_FEATURES) };
    let our_feat = dev_feat & (VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS);
    // SAFETY: write back the accepted subset.
    unsafe { outl(iobase + VIO_DRIVER_FEATURES, our_feat); }

    // Read MAC bytes (when F_MAC negotiated).
    let mut mac = [0u8; 6];
    if (our_feat & VIRTIO_NET_F_MAC) != 0 {
        for i in 0..6 {
            // SAFETY: reading the per-byte MAC config field.
            mac[i] = unsafe { inb(iobase + VIO_NET_MAC + i as u16) };
        }
    }

    // -- Queue setup (RX, TX) --
    // SAFETY: queue setup writes are serialized through this single-thread boot path.
    let rx = match unsafe { setup_queue(iobase, QUEUE_RX) } {
        Some(q) => q,
        None    => {
            // SAFETY: signal device-failed status so the device knows.
            unsafe { outb(iobase + VIO_DEVICE_STATUS, STATUS_FAILED); }
            return;
        }
    };
    let tx = match unsafe { setup_queue(iobase, QUEUE_TX) } {
        Some(q) => q,
        None    => {
            unsafe { outb(iobase + VIO_DEVICE_STATUS, STATUS_FAILED); }
            return;
        }
    };

    // -- DRIVER_OK --
    // SAFETY: signal driver ready per virtio handshake.
    unsafe {
        outb(iobase + VIO_DEVICE_STATUS,
             STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK);
    }

    *DEVICE.lock() = Some(VirtioNetDevice { iobase, mac, rx, tx });
    INITIALIZED.store(true, Ordering::Release);

    debug_boot! {
        klog::write_raw(b"[INFO]  virtio-net: ready iobase=");
        klog::write_hex_u64(iobase as u64);
        klog::write_raw(b" mac=");
        for (i, b) in mac.iter().enumerate() {
            klog::write_hex_u64(*b as u64);
            if i < 5 { klog::write_raw(b":"); }
        }
        klog::write_raw(b"\n");
    }

    // Touch the field counts so they're visible if klog tracing kicks
    // in later — keeps the optimizer honest about the queue regions
    // being live state, not dead writes.
    let _ = devs.len();
    let _ = dev.bdf;
    let _ = Vec::<u8>::new(); // kept for parity w/ alloc dependency.
}

/// Read + clear the ISR status byte. v1 doesn't yet wire IRQs, but
/// callers that poll the ISR need this. # C: O(1)
pub fn isr_read_clear() -> Option<u8> {
    let g = DEVICE.lock();
    let d = g.as_ref()?;
    // SAFETY: ISR_STATUS is read-clear per virtio spec; well-defined IO.
    Some(unsafe { inb(d.iobase + VIO_ISR_STATUS) })
}

/// Returns the device MAC, or None if no device.
/// # C: O(1)
pub fn mac() -> Option<[u8; 6]> {
    DEVICE.lock().as_ref().map(|d| d.mac)
}
