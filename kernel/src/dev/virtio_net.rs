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
// This module does steps 1-7 plus the TX data path (step 8 partial:
// driver→device frame transmit). RX descriptor pool + IRQ-driven
// completion drain stays in P19c/d. v1 TX is one-frame-at-a-time:
// we own one 4 KiB scratch page used as the per-call buffer,
// reclaim used-ring completions on each tx_frame call, and serialize
// behind DEVICE.lock().

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

/// VRING descriptor flag bits per Virtio 1.2 §2.6.5.
const VRING_DESC_F_NEXT:  u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

const PAGE_SIZE: u64 = 4096;
const HHDM_FALLBACK: u64 = 0xFFFF_8000_0000_0000; // matches pmm::user_as::hhdm_offset() default

/// One installed virtio-net device's runtime state.
pub struct VirtioNetDevice {
    pub iobase:    u16,
    pub mac:       [u8; 6],
    pub rx:        VirtQueueRuntime,
    pub tx:        VirtQueueRuntime,
    /// Single 4 KiB DMA-coherent scratch page reused across tx_frame
    /// calls. v1 holds one frame in flight; reclaimed via used-ring
    /// poll at the head of each tx_frame.
    pub tx_buf_pa: u64,
    pub tx_buf_va: u64,
    /// Per-RX-descriptor 4 KiB buffer pages. Queue size is capped at
    /// `RX_BUF_COUNT` ≤ queue size; each entry is one DMA-coherent
    /// page. The descriptor at index `i` permanently points at
    /// `rx_bufs[i].pa` for the device to write into; we re-publish
    /// the same chain head on each rx_poll completion.
    pub rx_bufs:   [RxBuf; RX_BUF_COUNT],
    /// How many RX descriptors actually got allocated (≤ rx.size).
    pub rx_count:  u16,
}

/// Per-RX-slot DMA-coherent receive buffer.
#[derive(Copy, Clone, Default)]
pub struct RxBuf {
    pub pa: u64,
    pub va: u64,
}

/// Maximum RX descriptors / buffers we pre-allocate at init.
/// Capped at the legacy queue size we negotiated (≤64).
pub const RX_BUF_COUNT: usize = 32;

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

    let pa = pmm::setup::alloc_one_frame()?;
    let va = pa + pmm::user_as::hhdm_offset();
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
    // SAFETY: queue setup writes serialized through this single-thread boot path; iobase from BAR0.
    let tx = match unsafe { setup_queue(iobase, QUEUE_TX) } {
        Some(q) => q,
        None    => {
            // SAFETY: signal device-failed status so the device knows we bailed.
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

    let tx_buf_pa = match pmm::setup::alloc_one_frame() {
        Some(p) => p,
        None => {
            // SAFETY: signal device-failed status when we can't get a tx scratch page.
            unsafe { outb(iobase + VIO_DEVICE_STATUS, STATUS_FAILED); }
            return;
        }
    };
    let tx_buf_va = tx_buf_pa + pmm::user_as::hhdm_offset();
    // SAFETY: HHDM-mapped scratch page; zero a single 4KiB region we just allocated.
    unsafe { core::ptr::write_bytes(tx_buf_va as *mut u8, 0, PAGE_SIZE as usize); }

    // Pre-allocate RX buffer pages and pin descriptors at indices
    // [0..rx_count). Each desc[i] = (rx_bufs[i].pa, PAGE_SIZE,
    // VRING_DESC_F_WRITE, 0). Avail ring pre-loaded with all
    // indices; avail.idx set to rx_count so the device sees them
    // ready when DRIVER_OK is written below.
    let target_rx = core::cmp::min(rx.size as usize, RX_BUF_COUNT);
    let mut rx_bufs = [RxBuf::default(); RX_BUF_COUNT];
    let mut rx_count: u16 = 0;
    for i in 0..target_rx {
        match pmm::setup::alloc_one_frame() {
            Some(pa) => {
                let va = pa + pmm::user_as::hhdm_offset();
                // SAFETY: HHDM-mapped page just allocated; zero before publishing.
                unsafe { core::ptr::write_bytes(va as *mut u8, 0, PAGE_SIZE as usize); }
                rx_bufs[i] = RxBuf { pa, va };
                rx_count += 1;
            }
            None => break,
        }
    }
    // SAFETY: rx region was set up by setup_queue → still HHDM-mapped, zeroed.
    unsafe {
        let desc_base  = rx.region_va;
        let avail_base = rx.region_va + avail_off(rx.size) as u64;
        for i in 0..rx_count as u64 {
            let d = desc_base + (i * 16);
            core::ptr::write_volatile(d as *mut u64,            rx_bufs[i as usize].pa);
            core::ptr::write_volatile((d + 8) as *mut u32,      PAGE_SIZE as u32);
            core::ptr::write_volatile((d + 12) as *mut u16,     VRING_DESC_F_WRITE);
            core::ptr::write_volatile((d + 14) as *mut u16,     0);
            core::ptr::write_volatile(
                (avail_base + 4 + i * 2) as *mut u16,
                i as u16,
            );
        }
        core::sync::atomic::fence(Ordering::Release);
        // avail.idx (offset +2) ← rx_count
        core::ptr::write_volatile((avail_base + 2) as *mut u16, rx_count);
        core::sync::atomic::fence(Ordering::Release);
    }
    let mut rx = rx;
    rx.next_avail = rx_count;

    *DEVICE.lock() = Some(VirtioNetDevice {
        iobase, mac, rx, tx, tx_buf_pa, tx_buf_va, rx_bufs, rx_count,
    });
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

// -------- TX data path (P19b) --------

const VIRTIO_NET_HDR_LEN: usize = 12;
/// Maximum frame the v1 TX scratch page can hold (PAGE_SIZE − header).
pub const TX_MAX_FRAME_LEN: usize = PAGE_SIZE as usize - VIRTIO_NET_HDR_LEN;

/// Errors from `tx_frame`. Distinct from `Errno` to keep the
/// virtio driver self-contained; callers (NetDev integration in
/// P19f) translate to errno.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TxErr {
    /// No virtio-net device installed.
    NoDev,
    /// Frame plus 12-byte header would exceed the scratch page.
    TooBig,
    /// Avail ring or descriptor pool exhausted (would only happen
    /// if a previous tx didn't complete and the device hasn't
    /// posted a used-ring entry — v1 holds one frame in flight).
    Busy,
}

/// `desc[idx]` byte offset within the queue region.
#[inline]
fn desc_off(idx: u16) -> usize { (idx as usize) * 16 }

/// `avail` byte offset (after desc table).
#[inline]
fn avail_off(qsize: u16) -> usize { (qsize as usize) * 16 }

/// `used` byte offset: avail tail rounded up to 4.
#[inline]
fn used_off(qsize: u16) -> usize {
    let avail_bytes = 6usize + 2 * (qsize as usize);
    (avail_off(qsize) + avail_bytes + 3) & !3
}

/// Reclaim any completed used-ring entries by advancing `last_used`.
/// v1 keeps a single descriptor in flight; this just keeps the
/// indices in lockstep so the next `tx_frame` doesn't see a stale
/// "Busy" condition.
/// # SAFETY: `region_va` is HHDM-mapped queue region for an
/// initialized virtio device under DEVICE.lock(); reads only.
unsafe fn reclaim_used(q: &mut VirtQueueRuntime) {
    let used_base = q.region_va + used_off(q.size) as u64;
    // SAFETY: queue region pinned + zero-initialized at setup; volatile
    // read for device-written used.idx field at offset 2.
    let dev_used_idx = unsafe {
        core::ptr::read_volatile((used_base + 2) as *const u16)
    };
    q.last_used = dev_used_idx;
}

/// Transmit one Ethernet frame through the legacy virtio-net TX
/// queue. Synchronous: returns once the descriptor + avail-ring
/// update has been published and QUEUE_NOTIFY kicked. Does NOT
/// wait for the device to ack (that needs P19d IRQs).
///
/// `frame` must be the L2 frame (Ethernet header + payload), NOT
/// the virtio_net_hdr — we prepend the 12-byte zero header inline.
///
/// # C: O(frame.len())
/// # Lk: takes `DEVICE` spinlock — IRQ-safe via `lock_irqsave`-class
///        Spinlock with `TaskList` class.
pub fn tx_frame(frame: &[u8]) -> Result<usize, TxErr> {
    if frame.len() > TX_MAX_FRAME_LEN { return Err(TxErr::TooBig); }
    let mut g = DEVICE.lock();
    let d = g.as_mut().ok_or(TxErr::NoDev)?;

    // Reclaim completions before publishing.
    // SAFETY: queue region is the page we set up in init_legacy(),
    // still HHDM-mapped, exclusive under DEVICE.lock().
    unsafe { reclaim_used(&mut d.tx); }

    // v1 single-in-flight check: we don't allow next_avail to
    // outrun last_used by more than `size` (would wrap into
    // unfreed slots). With size capped at 64 and 1 in flight,
    // this only triggers if the device stalled.
    let inflight = d.tx.next_avail.wrapping_sub(d.tx.last_used);
    if inflight >= d.tx.size {
        return Err(TxErr::Busy);
    }

    // Build [virtio_net_hdr (12 zero) | frame] in scratch buffer.
    // SAFETY: tx_buf_va is HHDM mapping of tx_buf_pa, which we
    // own exclusively under DEVICE.lock(); 12 + frame.len() ≤ PAGE_SIZE.
    unsafe {
        let dst = d.tx_buf_va as *mut u8;
        core::ptr::write_bytes(dst, 0, VIRTIO_NET_HDR_LEN);
        if !frame.is_empty() {
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                dst.add(VIRTIO_NET_HDR_LEN),
                frame.len(),
            );
        }
    }

    let total_len = (VIRTIO_NET_HDR_LEN + frame.len()) as u32;
    let slot      = d.tx.next_avail % d.tx.size;
    let desc_addr = d.tx.region_va + desc_off(slot) as u64;
    let avail_base = d.tx.region_va + avail_off(d.tx.size) as u64;

    // SAFETY: queue region is HHDM-mapped + exclusive under DEVICE.lock();
    // descriptor + avail-ring writes are aligned device-readable per
    // Virtio 1.2 §2.6 layout we set up at init.
    unsafe {
        // desc[slot] = { addr=tx_buf_pa, len=hdr+frame, flags=0, next=0 }
        core::ptr::write_volatile(desc_addr as *mut u64, d.tx_buf_pa);
        core::ptr::write_volatile((desc_addr + 8) as *mut u32, total_len);
        core::ptr::write_volatile((desc_addr + 12) as *mut u16, 0);
        core::ptr::write_volatile((desc_addr + 14) as *mut u16, 0);

        // avail.ring[slot] = slot   (avail.ring base at avail+4)
        core::ptr::write_volatile(
            (avail_base + 4 + (slot as u64) * 2) as *mut u16,
            slot,
        );
        // sfence — descriptor + ring slot must be visible before idx bump.
        core::sync::atomic::fence(Ordering::Release);
        // avail.idx (offset +2) ← next_avail+1
        let new_idx = d.tx.next_avail.wrapping_add(1);
        core::ptr::write_volatile((avail_base + 2) as *mut u16, new_idx);
        // sfence — idx must be visible before NOTIFY.
        core::sync::atomic::fence(Ordering::Release);

        // Kick: outw QUEUE_NOTIFY = QUEUE_TX
        outw(d.iobase + VIO_QUEUE_NOTIFY, QUEUE_TX);
    }

    d.tx.next_avail = d.tx.next_avail.wrapping_add(1);
    Ok(frame.len())
}

// -------- RX poll path (P19c) --------

/// Drain available RX completions and invoke `cb` with each frame
/// (Ethernet header + payload, virtio_net_hdr stripped). After the
/// callback returns, the descriptor is re-published to the device
/// so it can write the next frame into the same buffer.
///
/// Returns the number of frames delivered. v1 is poll-mode only;
/// callers drive this from a kthread or off the timer tick. IRQ
/// wiring lands in P19d.
///
/// # C: O(frames_in_flight)
/// # Lk: takes `DEVICE` spinlock around state mutation; the
///        callback runs WHILE the lock is held — keep it short.
pub fn rx_poll<F: FnMut(&[u8])>(mut cb: F) -> usize {
    let mut g = DEVICE.lock();
    let d = match g.as_mut() { Some(d) => d, None => return 0 };
    if d.rx_count == 0 { return 0; }

    let used_base  = d.rx.region_va + used_off(d.rx.size) as u64;
    let avail_base = d.rx.region_va + avail_off(d.rx.size) as u64;

    // SAFETY: queue region pinned + zero-initialized at setup; volatile
    // read for device-written used.idx field at offset 2.
    let dev_used_idx = unsafe {
        core::ptr::read_volatile((used_base + 2) as *const u16)
    };
    if dev_used_idx == d.rx.last_used { return 0; }

    let mut delivered = 0usize;
    let mut last_used = d.rx.last_used;
    while last_used != dev_used_idx {
        let slot = (last_used as usize) % (d.rx.size as usize);
        // used.ring[slot] = { id: u32, len: u32 } at offset 4 + slot*8.
        // SAFETY: device writes the used ring; we read after the volatile
        // idx fence above guarantees the entry is published.
        let (id, len) = unsafe {
            let base = used_base + 4 + (slot as u64) * 8;
            (
                core::ptr::read_volatile(base as *const u32),
                core::ptr::read_volatile((base + 4) as *const u32),
            )
        };
        last_used = last_used.wrapping_add(1);

        let id_u = id as usize;
        if id_u >= d.rx_count as usize { continue; }
        let buf_va = d.rx_bufs[id_u].va;
        let total  = len as usize;
        if total < VIRTIO_NET_HDR_LEN { continue; }
        let frame_len = total - VIRTIO_NET_HDR_LEN;
        if frame_len > PAGE_SIZE as usize - VIRTIO_NET_HDR_LEN { continue; }

        // SAFETY: rx_bufs[id].va is HHDM-mapped, owned exclusively
        // under DEVICE.lock(); device finished writing this slot
        // before populating used.ring (Virtio 1.2 §2.6.8).
        let frame = unsafe {
            core::slice::from_raw_parts(
                (buf_va + VIRTIO_NET_HDR_LEN as u64) as *const u8,
                frame_len,
            )
        };
        cb(frame);
        delivered += 1;

        // Re-publish desc id back to the device by appending to
        // avail.ring at next_avail % size and bumping avail.idx.
        let pub_slot = (d.rx.next_avail as usize) % (d.rx.size as usize);
        // SAFETY: avail ring is HHDM-mapped + exclusive under DEVICE.lock().
        unsafe {
            core::ptr::write_volatile(
                (avail_base + 4 + (pub_slot as u64) * 2) as *mut u16,
                id as u16,
            );
            core::sync::atomic::fence(Ordering::Release);
            let new_idx = d.rx.next_avail.wrapping_add(1);
            core::ptr::write_volatile((avail_base + 2) as *mut u16, new_idx);
            core::sync::atomic::fence(Ordering::Release);
        }
        d.rx.next_avail = d.rx.next_avail.wrapping_add(1);
    }
    d.rx.last_used = last_used;

    // One kick after batched re-publish so the device knows we
    // refilled the ring. Cheap; legacy port-IO.
    // SAFETY: NOTIFY is a write-only port per Virtio 1.2 §4.1.4.4.
    unsafe { outw(d.iobase + VIO_QUEUE_NOTIFY, QUEUE_RX); }
    delivered
}
