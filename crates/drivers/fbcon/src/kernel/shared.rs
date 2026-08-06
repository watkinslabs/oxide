extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use sync::{Spinlock, Tty as TtyClass};
use vtdata::{Emulator, Vc, N_VT};

use crate::damage::FlushRect;
use crate::vcrender::VcRenderer;

pub(crate) struct VcCell {
    pub(crate) vc: Vc,
    pub(crate) em: Emulator,
}

pub(crate) const N_SLOTS: usize = N_VT + 1;

pub(crate) struct VtState {
    pub(crate) vc_cons: [Option<Box<VcCell>>; N_SLOTS],
    pub(crate) graphics: [bool; N_SLOTS],
    pub(crate) fg: u8,
    pub(crate) renderer: VcRenderer,
    pub(crate) cols: u16,
    pub(crate) rows: u16,
}

impl VtState {
    pub(crate) fn ensure(&mut self, vt: u8) -> usize {
        let i = (vt as usize).min(N_SLOTS - 1);
        if self.vc_cons[i].is_none() {
            self.vc_cons[i] = Some(Box::new(VcCell {
                vc: Vc::new(self.cols, self.rows),
                em: Emulator::new(),
            }));
        }
        i
    }
}

// `VT_STATE` is shared between PROCESS context (every console write, VT switch
// and query below) and the `FbconFlush` SOFTIRQ (`flush_softirq` -> `repaint`).
// A process-context holder must therefore exclude this CPU's bottom halves
// (Linux `spin_lock_bh`): without that, an interrupt landing inside the
// critical section runs the softirq drain on its way out, `repaint` spins for a
// lock the interrupted context on the SAME processor already holds, and that
// processor never makes progress again.
//
// This only bites where interrupts are actually unmasked. A syscall runs with
// them masked, so userspace-driven console traffic could never expose it; a
// kernel thread does not, so the first in-kernel writer to reach the console
// wedged the machine. Every process-context acquisition goes through
// [`lock_vt`] / [`try_lock_vt`]; the softirq's own acquisition stays plain,
// because it is already running with bottom halves accounted for.
pub(crate) static VT_STATE: Spinlock<Option<VtState>, TtyClass> = Spinlock::new(None);

// Hosted tests mutate one process-global fbcon domain: `VT_STATE`, answerback
// queues/PENDING, the kernel registration install, the `FbconFlush` softirq
// slot and the preempt count. Module-private serialization statics do not
// exclude each other. The lock belongs to the shared state, so this is the
// ONLY serialization an fbcon test may take. It ranks above `TtyClass` so
// `VT_STATE` and answerback queues nest inside it.
#[cfg(test)]
pub(crate) static CONSOLE_TEST_DOMAIN: Spinlock<(), sync::Devices> = Spinlock::new(());

/// The bottom-half gate `spin_lock_bh` needs. `sync` sits below `sched` and
/// cannot reach the preempt count itself, so the gate arrives as a type.
type Bh = sched::bh::SchedBh;

/// Process-context acquisition of [`VT_STATE`], Linux `spin_lock_bh`.
/// # C: O(contention)
pub(crate) fn lock_vt() -> sync::LockBhGuard<'static, Option<VtState>, TtyClass, Bh> {
    VT_STATE.lock_bh::<Bh>()
}

/// Non-blocking process-context acquisition, for callers that must never wait
/// on the console (the klog sink, mode queries). Bottom halves stay disabled
/// for as long as the returned guard lives.
///
/// Re-enabling does NOT drain: this is the acquisition the log sink uses, and
/// the log sink is reachable from inside any other subsystem's critical
/// section, so running softirq handlers on the way out could re-enter a lock
/// the caller already holds. The sink re-raises `FbconFlush` regardless, so the
/// repaint is deferred, never dropped.
/// # C: O(1)
pub(crate) fn try_lock_vt() -> Option<VtBhGuard> {
    let bh = sched::bh::BhGuardNoDrain::new();
    match VT_STATE.try_lock() {
        // Field order is the drop order: the lock releases before bottom
        // halves come back.
        Some(inner) => Some(VtBhGuard { inner, _bh: bh }),
        None => None,
    }
}

/// A held [`VT_STATE`] plus the bottom-half disable that guards it.
pub(crate) struct VtBhGuard {
    inner: sync::Guard<'static, Option<VtState>, TtyClass>,
    _bh: sched::bh::BhGuardNoDrain,
}

impl core::ops::Deref for VtBhGuard {
    type Target = Option<VtState>;
    fn deref(&self) -> &Option<VtState> { &self.inner }
}
impl core::ops::DerefMut for VtBhGuard {
    fn deref_mut(&mut self) -> &mut Option<VtState> { &mut self.inner }
}

pub(crate) fn pixels_as_bytes(px: &[u32]) -> &[u8] {
    // SAFETY: reinterpreting an initialized `[u32]` as `[u8]` of four times the
    // length — u8's alignment of 1 is satisfied by any u32 pointer, every byte
    // is initialized, and the borrow keeps `px` alive for the result's lifetime.
    // `len() * 4` cannot overflow: the source slice already exists in memory.
    unsafe { core::slice::from_raw_parts(px.as_ptr() as *const u8, px.len() * 4) }
}

/// Sink for a repaint: `pixels` is the WHOLE 0x00RRGGBB surface as bytes,
/// `rect` names the only part of it that changed. The sink must upload just
/// `rect`, indexing `pixels` at `rect.stride_px` — that is what keeps one
/// changed console line from costing a whole-frame copy plus a whole-screen
/// device round-trip.
pub type FlushFn = fn(pixels: &[u8], rect: FlushRect);
pub(crate) static FLUSH_FN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

pub type ReplyFn = crate::answerback::ReplyFn;

pub(crate) static READY: AtomicBool = AtomicBool::new(false);
pub(crate) static DIRTY: AtomicBool = AtomicBool::new(false);

/// The `FbconFlush` handler. Runs in softirq context, where bottom halves are
/// already accounted for on this processor, so the plain acquisition is the
/// correct one — and the only one in the file. # C: O(damaged region)
pub(crate) fn flush_softirq() {
    if !DIRTY.swap(false, Ordering::AcqRel) {
        return;
    }
    let mut g = VT_STATE.lock();
    blit(g.as_mut());
}

/// Process-context repaint (console bring-up). # C: O(damaged region)
pub(crate) fn repaint() {
    let mut g = lock_vt();
    blit(g.as_mut());
}

/// Hand the accumulated damage to the flush sink, then forget it. The take
/// happens only once a sink exists to consume it, so a repaint raised before
/// `kernel_init` installs one is deferred rather than dropped.
fn blit(st: Option<&mut VtState>) {
    let raw = FLUSH_FN.load(Ordering::Acquire);
    if raw.is_null() {
        return;
    }
    // SAFETY: FLUSH_FN is only ever stored by `kernel_init` from a `FlushFn`
    // cast through `*mut ()`; the reverse cast restores that exact signature.
    let f: FlushFn = unsafe { core::mem::transmute::<*mut (), FlushFn>(raw) };
    if let Some(st) = st {
        if let Some(rect) = st.renderer.take_damage() {
            f(pixels_as_bytes(st.renderer.pixels()), rect);
        }
    }
}

pub(crate) fn queue_answerback(vt: u8, bytes: &[u8]) {
    crate::answerback::queue(vt, bytes);
}
