extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use sync::{Spinlock, Tty as TtyClass};
use vtdata::{Emulator, Vc, N_VT};

use crate::vcrender::VcRenderer;

pub(crate) struct VcCell {
    pub(crate) vc: Vc,
    pub(crate) em: Emulator,
}

pub(crate) const N_SLOTS: usize = N_VT + 1;

pub(crate) struct VtState {
    pub(crate) vc_cons: [Option<Box<VcCell>>; N_SLOTS],
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

pub(crate) static VT_STATE: Spinlock<Option<VtState>, TtyClass> = Spinlock::new(None);

pub(crate) fn pixels_as_bytes(px: &[u32]) -> &[u8] {
    unsafe { core::slice::from_raw_parts(px.as_ptr() as *const u8, px.len() * 4) }
}

pub type FlushFn = fn(pixels: &[u8]);
pub(crate) static FLUSH_FN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

pub type ReplyFn = crate::answerback::ReplyFn;

pub(crate) static READY: AtomicBool = AtomicBool::new(false);
pub(crate) static DIRTY: AtomicBool = AtomicBool::new(false);

pub(crate) fn flush_softirq() {
    if !DIRTY.swap(false, Ordering::AcqRel) {
        return;
    }
    repaint();
}

pub(crate) fn repaint() {
    let raw = FLUSH_FN.load(Ordering::Acquire);
    if raw.is_null() {
        return;
    }
    let f: FlushFn = unsafe { core::mem::transmute::<*mut (), FlushFn>(raw) };
    let guard = VT_STATE.lock();
    if let Some(st) = guard.as_ref() {
        f(pixels_as_bytes(st.renderer.pixels()));
    }
}

pub(crate) fn queue_answerback(vt: u8, bytes: &[u8]) {
    crate::answerback::queue(vt, bytes);
}
