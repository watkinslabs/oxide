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

use crate::keymap::{self, Mods, Side, Out};
use crate::{VirtioInputEvent, EV_KEY};

// Linux KEY_* identifiers for modifier keys. The keymap text file
// owns *printable* keycodes; modifiers stay hard-wired here so a
// broken keymap can never lock the user out of layout switching.
const KEY_LEFTCTRL:    u16 = 29;
const KEY_LEFTSHIFT:   u16 = 42;
const KEY_RIGHTSHIFT:  u16 = 54;
const KEY_LEFTALT:     u16 = 56;
const KEY_CAPSLOCK:    u16 = 58;
const KEY_NUMLOCK:     u16 = 69;
const KEY_SCROLLLOCK:  u16 = 70;
const KEY_RIGHTCTRL:   u16 = 97;
const KEY_RIGHTALT:    u16 = 100;     // a.k.a. AltGr
const KEY_LEFTMETA:    u16 = 125;     // Super / Win
const KEY_RIGHTMETA:   u16 = 126;

/// Update the keymap modifier state for `keycode`. Returns `true`
/// iff the keycode was a modifier and should not be translated as
/// a printable key.
fn handle_modifier(keycode: u16, pressed: bool) -> bool {
    match keycode {
        KEY_LEFTSHIFT   => { keymap::set_side(Side::ShiftLeft,  pressed); true }
        KEY_RIGHTSHIFT  => { keymap::set_side(Side::ShiftRight, pressed); true }
        KEY_LEFTCTRL    => { keymap::set_side(Side::CtrlLeft,   pressed); true }
        KEY_RIGHTCTRL   => { keymap::set_side(Side::CtrlRight,  pressed); true }
        KEY_LEFTALT     => { keymap::set_side(Side::AltLeft,    pressed); true }
        KEY_RIGHTALT    => { keymap::set_side(Side::AltRight,   pressed); true }
        KEY_LEFTMETA | KEY_RIGHTMETA => { keymap::set_mod(Mods::META, pressed); true }
        KEY_CAPSLOCK    => { if pressed { keymap::toggle_lock(Mods::CAPS); }   true }
        KEY_NUMLOCK     => { if pressed { keymap::toggle_lock(Mods::NUM); }    true }
        KEY_SCROLLLOCK  => { if pressed { keymap::toggle_lock(Mods::SCROLL); } true }
        _ => false,
    }
}

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

        // EV_KEY: value=1 press, value=2 autorepeat, value=0 release.
        if evt.ty == EV_KEY {
            let pressed = evt.value == 1 || evt.value == 2;
            // Modifier keys feed the keymap state machine and never
            // produce input bytes themselves.
            if !handle_modifier(evt.code, pressed) && pressed {
                let out = keymap::translate(evt.code);
                out.for_each(|b| {
                    tty::live::input_push_byte(b);
                    DRAINED_KEYS.fetch_add(1, Ordering::Relaxed);
                });
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

