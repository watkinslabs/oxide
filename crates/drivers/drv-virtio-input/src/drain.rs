// Event-queue drain for virtio-input. Owns the q0 RX-buffer pool +
// the softirq handler that walks the used ring and bridges Linux
// `input_event`s to the foreground VT's line discipline.
//
// Wire-up (boot path)
//   pci_boot::virtio_drv runs the modern PCI bring-up: features,
//   queue setup, DRIVER_OK. Then it calls `install_q0` here with
//   the per-device queue descriptors so this module can pre-fill
//   the event ring and stash state for the softirq handler.
//
// Runtime (per timer tick)
//   `softirq::Slot::InputDrain` handler reads `device_pa->idx`,
//   walks new used entries, recycles their descriptors back to
//   the avail ring, parses each 8-byte `VirtioInputEvent`, and for
//   each EV_KEY press maps the keycode to ASCII via `KEY_TO_ASCII`
//   and pushes through `tty::live::input_push_byte`.
//
// Why softirq, not the device IRQ directly
//   The drain reads device-written used entries which become visible
//   only after the device's completion interrupt — so the actual
//   ring walk must run *after* IRQs are unmasked. The device IRQ
//   raises the softirq slot; the timer ISR tail (see arch-irq) runs
//   the drain with IRQs enabled. Same shape as Linux NET_RX.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{VirtioInputEvent, EV_KEY};

// Linux input-event-codes.h subset. KEY_* codes used by QEMU's
// virtio-keyboard for ASCII-mapped keys; everything else is 0 in
// the translation table.
const KEY_RESERVED:    u16 = 0;
const KEY_ESC:         u16 = 1;
const KEY_1:           u16 = 2;
const KEY_MINUS:       u16 = 12;
const KEY_EQUAL:       u16 = 13;
const KEY_BACKSPACE:   u16 = 14;
const KEY_TAB:         u16 = 15;
const KEY_Q:           u16 = 16;
const KEY_ENTER:       u16 = 28;
const KEY_LEFTCTRL:    u16 = 29;
const KEY_A:           u16 = 30;
const KEY_SEMICOLON:   u16 = 39;
const KEY_APOSTROPHE:  u16 = 40;
const KEY_GRAVE:       u16 = 41;
const KEY_LEFTSHIFT:   u16 = 42;
const KEY_BACKSLASH:   u16 = 43;
const KEY_Z:           u16 = 44;
const KEY_M:           u16 = 50;
const KEY_COMMA:       u16 = 51;
const KEY_DOT:         u16 = 52;
const KEY_SLASH:       u16 = 53;
const KEY_RIGHTSHIFT:  u16 = 54;
const KEY_SPACE:       u16 = 57;
const KEY_LEFTBRACE:   u16 = 26;
const KEY_RIGHTBRACE:  u16 = 27;
const KEY_LEFTALT:     u16 = 56;
const KEY_CAPSLOCK:    u16 = 58;

/// US-QWERTY scancode → ASCII (unshifted). Indexed by Linux KEY_*.
/// Zero = no translation (function keys, modifiers, etc.).
const KEY_TO_ASCII_LOWER: [u8; 128] = {
    let mut t = [0u8; 128];
    t[KEY_1 as usize]          = b'1';
    t[(KEY_1 + 1) as usize]    = b'2';
    t[(KEY_1 + 2) as usize]    = b'3';
    t[(KEY_1 + 3) as usize]    = b'4';
    t[(KEY_1 + 4) as usize]    = b'5';
    t[(KEY_1 + 5) as usize]    = b'6';
    t[(KEY_1 + 6) as usize]    = b'7';
    t[(KEY_1 + 7) as usize]    = b'8';
    t[(KEY_1 + 8) as usize]    = b'9';
    t[(KEY_1 + 9) as usize]    = b'0';
    t[KEY_MINUS as usize]      = b'-';
    t[KEY_EQUAL as usize]      = b'=';
    t[KEY_BACKSPACE as usize]  = 0x7f;
    t[KEY_TAB as usize]        = b'\t';
    t[KEY_Q as usize]          = b'q';
    t[(KEY_Q + 1) as usize]    = b'w';
    t[(KEY_Q + 2) as usize]    = b'e';
    t[(KEY_Q + 3) as usize]    = b'r';
    t[(KEY_Q + 4) as usize]    = b't';
    t[(KEY_Q + 5) as usize]    = b'y';
    t[(KEY_Q + 6) as usize]    = b'u';
    t[(KEY_Q + 7) as usize]    = b'i';
    t[(KEY_Q + 8) as usize]    = b'o';
    t[(KEY_Q + 9) as usize]    = b'p';
    t[KEY_LEFTBRACE as usize]  = b'[';
    t[KEY_RIGHTBRACE as usize] = b']';
    t[KEY_ENTER as usize]      = b'\n';
    t[KEY_A as usize]          = b'a';
    t[(KEY_A + 1) as usize]    = b's';
    t[(KEY_A + 2) as usize]    = b'd';
    t[(KEY_A + 3) as usize]    = b'f';
    t[(KEY_A + 4) as usize]    = b'g';
    t[(KEY_A + 5) as usize]    = b'h';
    t[(KEY_A + 6) as usize]    = b'j';
    t[(KEY_A + 7) as usize]    = b'k';
    t[(KEY_A + 8) as usize]    = b'l';
    t[KEY_SEMICOLON as usize]  = b';';
    t[KEY_APOSTROPHE as usize] = b'\'';
    t[KEY_GRAVE as usize]      = b'`';
    t[KEY_BACKSLASH as usize]  = b'\\';
    t[KEY_Z as usize]          = b'z';
    t[(KEY_Z + 1) as usize]    = b'x';
    t[(KEY_Z + 2) as usize]    = b'c';
    t[(KEY_Z + 3) as usize]    = b'v';
    t[(KEY_Z + 4) as usize]    = b'b';
    t[(KEY_Z + 5) as usize]    = b'n';
    t[KEY_M as usize]          = b'm';
    t[KEY_COMMA as usize]      = b',';
    t[KEY_DOT as usize]        = b'.';
    t[KEY_SLASH as usize]      = b'/';
    t[KEY_SPACE as usize]      = b' ';
    t[KEY_ESC as usize]        = 0x1b;
    let _ = KEY_RESERVED; let _ = KEY_LEFTCTRL; let _ = KEY_LEFTSHIFT;
    let _ = KEY_RIGHTSHIFT; let _ = KEY_LEFTALT; let _ = KEY_CAPSLOCK;
    t
};

/// Per-virtio-input-device runtime state. Captured at boot via
/// `install_q0`; consumed by the softirq drain.
struct QueueCtx {
    hhdm:        u64,
    desc_pa:     u64,
    driver_pa:   u64,    // avail ring base
    device_pa:   u64,    // used  ring base
    notify_va:   u64,
    qsize:       u16,
    /// Page-allocated event-buffer pool: `qsize` × 8 bytes.
    buf_pa:      u64,
    /// Driver-side: last `used.idx` we drained.
    last_used:   u16,
    /// Driver-side: avail.idx we last wrote.
    avail_idx:   u16,
}

/// Up to 8 input devices share one drain (kbd + mouse + ...).
static CTXS: Spinlock<[Option<QueueCtx>; 8], DriverLockClass> =
    Spinlock::new([const { None }; 8]);

/// Slot count for diag.
pub static DRAINED_EVENTS: AtomicU64 = AtomicU64::new(0);
pub static DRAINED_KEYS:   AtomicU64 = AtomicU64::new(0);

static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install per-device queue context after DRIVER_OK. Pre-fills the
/// event ring with `qsize` write-only descriptors, each pointing
/// at an 8-byte slot in a page-allocated buffer pool.
///
/// Returns `Ok(())` on success; `Err(())` if the buffer allocation
/// failed (in which case the device's events are simply not drained,
/// boot continues).
///
/// # SAFETY
/// Caller owns the queue: `desc_pa`, `driver_pa`, `device_pa`,
/// `notify_va` are valid for the duration of the kernel and the
/// device is in DRIVER_OK state. HHDM-mapped writes to these
/// addresses are safe at CPL=0.
/// # C: O(qsize)
pub unsafe fn install_q0(
    bdf: u32,
    qsize: u16,
    desc_pa: u64,
    driver_pa: u64,
    device_pa: u64,
    notify_va: u64,
    hhdm: u64,
) -> Result<(), ()> {
    let _ = bdf;
    // Allocate one 4 KiB frame; 512 events × 8B fits 64 events easily.
    let buf_pa = match pmm::setup::alloc_one_frame() { Some(pa) => pa, None => return Err(()) };
    // SAFETY: HHDM-mapped contiguous frame; bounded writes within 4 KiB.
    unsafe {
        let buf_va = hhdm.wrapping_add(buf_pa) as *mut u8;
        for i in 0..0x1000usize { core::ptr::write_volatile(buf_va.add(i), 0); }
    }
    // Pre-fill descriptors: each desc[i] points to buf_pa + i*8, len=8, WRITE flag.
    let desc_va = hhdm.wrapping_add(desc_pa) as *mut u8;
    // SAFETY: HHDM-mapped queue desc array; qsize * 16 ≤ 1 KiB ≪ HHDM mapping.
    unsafe {
        for i in 0..qsize as usize {
            let entry_pa = buf_pa.wrapping_add((i as u64) * 8);
            let off = i * 16;
            core::ptr::write_volatile(desc_va.add(off)        as *mut u64, entry_pa);
            core::ptr::write_volatile(desc_va.add(off + 8)    as *mut u32, 8u32);
            core::ptr::write_volatile(desc_va.add(off + 12)   as *mut u16, virtio::queue::VRING_DESC_F_WRITE);
            core::ptr::write_volatile(desc_va.add(off + 14)   as *mut u16, 0u16);
        }
    }
    // Avail ring at driver_pa: layout per virtio 1.2 §2.6.6 split.
    //   u16 flags @ 0; u16 idx @ 2; u16 ring[qsize] @ 4; u16 used_event @ 4+2*qsize
    let avail_va = hhdm.wrapping_add(driver_pa) as *mut u8;
    // SAFETY: same as above; bounded writes within driver_pa's 4 KiB frame.
    unsafe {
        core::ptr::write_volatile(avail_va        as *mut u16, 0u16);             // flags
        for i in 0..qsize as usize {
            let off = 4 + i * 2;
            core::ptr::write_volatile(avail_va.add(off) as *mut u16, i as u16);
        }
        core::ptr::write_volatile(avail_va.add(2) as *mut u16, qsize);            // idx = qsize (all posted)
    }
    // Find a free CTX slot.
    {
        let mut g = CTXS.lock();
        for slot in g.iter_mut() {
            if slot.is_none() {
                *slot = Some(QueueCtx {
                    hhdm, desc_pa, driver_pa, device_pa, notify_va,
                    qsize, buf_pa, last_used: 0, avail_idx: qsize,
                });
                break;
            }
        }
    }
    if !HANDLER_INSTALLED.swap(true, Ordering::AcqRel) {
        softirq::set_handler(softirq::Slot::InputDrain, drain_softirq);
    }
    // Notify the device that buffers are available.
    // SAFETY: notify_va is the per-queue notification register VA published by the device cfg; u16 store of queue index (0).
    unsafe { core::ptr::write_volatile(notify_va as *mut u16, 0u16); }
    Ok(())
}

/// Raise the InputDrain softirq. Called from the virtio-input
/// device IRQ (MSI vector handler) — runs with IRQs masked, just
/// flips the pending bit; actual drain happens with IRQs on.
/// # C: O(1)
pub fn raise_drain() { softirq::raise(softirq::Slot::InputDrain); }

/// Softirq handler — walks the used ring for every installed
/// virtio-input device, dispatches events, recycles buffers.
/// # Ctx: process / softirq, IRQs enabled.
/// # C: O(n_pending × n_devices)
fn drain_softirq() {
    let mut g = CTXS.lock();
    for slot in g.iter_mut() {
        let ctx = match slot.as_mut() { Some(c) => c, None => continue };
        drain_one(ctx);
    }
}

fn drain_one(ctx: &mut QueueCtx) {
    // Used ring layout at device_pa: u16 flags @ 0; u16 idx @ 2;
    // UsedElem { u32 id; u32 len } ring[qsize] @ 4; u16 avail_event @ tail.
    let used_va = ctx.hhdm.wrapping_add(ctx.device_pa) as *mut u8;
    // SAFETY: HHDM-mapped used-ring base; aligned u16 load of device-written idx field.
    let dev_idx = unsafe { core::ptr::read_volatile(used_va.add(2) as *const u16) };
    if dev_idx == ctx.last_used { return; }

    while ctx.last_used != dev_idx {
        let i = (ctx.last_used as usize) & (ctx.qsize as usize - 1);
        let off = 4 + i * 8;
        // SAFETY: bounded u32 reads within used ring; qsize is a power of two and < 4 KiB total.
        let desc_id = unsafe { core::ptr::read_volatile(used_va.add(off) as *const u32) } as u16;
        // event buffer lives at buf_pa + desc_id*8 (we set up the
        // identity mapping in install_q0).
        let evt_pa = ctx.buf_pa.wrapping_add((desc_id as u64) * 8);
        let evt_va = ctx.hhdm.wrapping_add(evt_pa) as *const VirtioInputEvent;
        // SAFETY: 8-byte event slot inside our buffer pool; read_volatile to defeat caching.
        let evt = unsafe { core::ptr::read_volatile(evt_va) };
        DRAINED_EVENTS.fetch_add(1, Ordering::Relaxed);

        // Map EV_KEY press → ASCII → foreground VT.
        if evt.ty == EV_KEY && evt.value == 1 {
            let kc = evt.code as usize;
            if kc < KEY_TO_ASCII_LOWER.len() {
                let ascii = KEY_TO_ASCII_LOWER[kc];
                if ascii != 0 {
                    tty::live::input_push_byte(ascii);
                    DRAINED_KEYS.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // Recycle: re-add this descriptor to the avail ring.
        let avail_va = ctx.hhdm.wrapping_add(ctx.driver_pa) as *mut u8;
        let avail_slot = (ctx.avail_idx as usize) & (ctx.qsize as usize - 1);
        let avail_off = 4 + avail_slot * 2;
        // SAFETY: bounded u16 write inside the avail ring buffer (4 KiB frame).
        unsafe { core::ptr::write_volatile(avail_va.add(avail_off) as *mut u16, desc_id); }
        ctx.avail_idx = ctx.avail_idx.wrapping_add(1);
        ctx.last_used = ctx.last_used.wrapping_add(1);
    }

    // Publish new avail.idx + notify device.
    let avail_va = ctx.hhdm.wrapping_add(ctx.driver_pa) as *mut u8;
    // SAFETY: aligned u16 store of the new avail.idx; pair with device-side read fence in QEMU's virtio backend.
    unsafe { core::ptr::write_volatile(avail_va.add(2) as *mut u16, ctx.avail_idx); }
    // SAFETY: queue notify register VA; u16 store of the queue index (0).
    unsafe { core::ptr::write_volatile(ctx.notify_va as *mut u16, 0u16); }
}

