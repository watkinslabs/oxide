use core::sync::atomic::Ordering;
use vtdata::Consw;

use crate::kernel::shared::{
    queue_answerback, DIRTY, FLUSH_FN, READY, ReplyFn, VcCell, VtState, VT_STATE,
    FlushFn, flush_softirq,
};

pub fn set_reply_sink(f: ReplyFn) {
    crate::answerback::set_sink(f);
}

pub fn drain_answerback() {
    crate::answerback::drain();
}

pub fn kernel_init(xres: u32, yres: u32, flush: FlushFn) {
    softirq::set_handler(softirq::Slot::FbconFlush, flush_softirq);
    let font = crate::font::active();
    let (cell_w, cell_h) = (font.width.max(1), font.height.max(1));
    let cols = (xres / cell_w).max(1) as u16;
    let rows = (yres / cell_h).max(1) as u16;
    let mut renderer = crate::vcrender::VcRenderer::new();
    renderer.con_init(cols as u32, rows as u32);
    let mut sys = alloc::boxed::Box::new(VcCell {
        vc: vtdata::Vc::new(cols, rows),
        em: vtdata::Emulator::new(),
    });
    vtdata::switch(&mut sys.vc, &mut renderer);
    let mut vc_cons: [Option<alloc::boxed::Box<VcCell>>; crate::kernel::shared::N_SLOTS] =
        [const { None }; crate::kernel::shared::N_SLOTS];
    vc_cons[1] = Some(sys);
    *VT_STATE.lock() = Some(VtState { vc_cons, fg: 1, renderer, cols, rows });
    FLUSH_FN.store(flush as *mut (), Ordering::Release);
    READY.store(true, Ordering::Release);
    DIRTY.store(true, Ordering::Release);
    crate::kernel::shared::repaint();
}

pub fn kernel_unregister() {
    READY.store(false, Ordering::Release);
    DIRTY.store(false, Ordering::Release);
    FLUSH_FN.store(core::ptr::null_mut(), Ordering::Release);
    crate::answerback::clear_sink();
    *VT_STATE.lock() = None;
}

pub fn vt_console_sink(bytes: &[u8]) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    if let Some(mut g) = VT_STATE.try_lock() {
        if let Some(st) = g.as_mut() {
            let i = st.ensure(st.fg);
            if let Some(cell) = st.vc_cons[i].as_mut() {
                let mut start = 0;
                for k in 0..bytes.len() {
                    if bytes[k] == b'\n' {
                        cell.em.feed_bytes(&mut cell.vc, &bytes[start..k]);
                        cell.em.feed_bytes(&mut cell.vc, b"\r\n");
                        start = k + 1;
                    }
                }
                if start < bytes.len() {
                    cell.em.feed_bytes(&mut cell.vc, &bytes[start..]);
                }
                vtdata::render(&mut cell.vc, &mut st.renderer);
                DIRTY.store(true, Ordering::Release);
                let _ = cell.em.take_reply();
            }
        }
    }
    softirq::raise(softirq::Slot::FbconFlush);
}

pub fn tick_drain() {
    drain_answerback();
}

pub fn vt_write(vt: u8, bytes: &[u8]) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    let mut blitted = false;
    let mut reply: Option<vtdata::ReplyBytes> = None;
    {
        let mut guard = VT_STATE.lock();
        if let Some(st) = guard.as_mut() {
            let i = st.ensure(vt);
            let is_fg = i == st.fg as usize;
            if let Some(cell) = st.vc_cons[i].as_mut() {
                cell.em.feed_bytes(&mut cell.vc, bytes);
                if is_fg {
                    vtdata::render(&mut cell.vc, &mut st.renderer);
                    DIRTY.store(true, Ordering::Release);
                    blitted = true;
                }
                let r = cell.em.take_reply();
                if !r.is_empty() {
                    reply = Some(r);
                }
            }
        }
    }
    if let Some(r) = reply {
        queue_answerback(vt, r.as_slice());
    }
    if blitted {
        softirq::raise(softirq::Slot::FbconFlush);
    }
}

pub fn switch_vt(n: u8) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    {
        let mut guard = VT_STATE.lock();
        if let Some(st) = guard.as_mut() {
            let i = st.ensure(n);
            st.fg = i as u8;
            if let Some(cell) = st.vc_cons[i].as_mut() {
                vtdata::switch(&mut cell.vc, &mut st.renderer);
                DIRTY.store(true, Ordering::Release);
            }
        }
    }
    softirq::raise(softirq::Slot::FbconFlush);
}
