use core::sync::atomic::Ordering;
use vtdata::Consw;

use crate::kernel::shared::{
    lock_vt, queue_answerback, queue_flush, try_lock_vt, DIRTY, FLUSH_FN, GEOMETRY_SINK, READY,
    SUSPENDED, GeometrySink, ReplyFn, VcCell, VtState, FlushFn, flush_softirq,
};

pub fn set_reply_sink(f: ReplyFn) {
    crate::answerback::set_sink(f);
}

pub fn drain_answerback() {
    crate::answerback::drain();
}

/// Register the numbered-VT geometry consumer and converge it immediately
/// when fbcon is already live.
/// # C: O(1)
pub fn set_geometry_sink(f: GeometrySink) {
    GEOMETRY_SINK.store(f as *mut (), Ordering::Release);
    let geometry = lock_vt().as_ref().map(|st| (st.rows, st.cols, st.ypixel));
    if let Some((rows, cols, ypixel)) = geometry {
        f(rows, cols, ypixel);
    }
}

/// Publish a committed text geometry after the fbcon state lock is released.
/// # C: O(1)
fn publish_geometry(rows: u16, cols: u16, ypixel: u16) {
    let raw = GEOMETRY_SINK.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: GEOMETRY_SINK is written only by set_geometry_sink from a
    // GeometrySink function pointer cast through `*mut ()`; this restores the
    // exact signature after all fbcon state for the new geometry is committed.
    let f: GeometrySink = unsafe { core::mem::transmute::<*mut (), GeometrySink>(raw) };
    f(rows, cols, ypixel);
}

pub fn kernel_init(xres: u32, yres: u32, flush: FlushFn) {
    softirq::set_handler(softirq::Slot::FbconFlush, flush_softirq);
    let (cols, rows) = text_geometry(xres, yres);
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
    *lock_vt() = Some(VtState {
        vc_cons,
        graphics: [false; crate::kernel::shared::N_SLOTS],
        fg: 1,
        renderer,
        cols,
        rows,
        ypixel: yres.min(u32::from(u16::MAX)) as u16,
    });
    FLUSH_FN.store(flush as *mut (), Ordering::Release);
    READY.store(true, Ordering::Release);
    DIRTY.store(true, Ordering::Release);
    publish_geometry(rows, cols, yres.min(u32::from(u16::MAX)) as u16);
    crate::kernel::shared::repaint();
}

/// Replace the scanout sink and resize every live VT to its visible geometry.
///
/// Firmware and native scanouts can report different modes. The native
/// framebuffer owns the new text grid, while each `Vc` preserves the cells it
/// already contains before the foreground is rendered into the new surface.
/// # C: O(framebuffer pixels)
pub fn kernel_rebind(xres: u32, yres: u32, flush: FlushFn) -> bool {
    if !READY.load(Ordering::Acquire) || xres == 0 || yres == 0 { return false; }
    let (cols, rows) = text_geometry(xres, yres);
    let mut repaint = false;
    {
        let mut guard = lock_vt();
        let Some(st) = guard.as_mut() else { return false; };
        st.cols = cols;
        st.rows = rows;
        st.ypixel = yres.min(u32::from(u16::MAX)) as u16;
        for cell in st.vc_cons.iter_mut().flatten() {
            cell.vc.resize(cols, rows);
        }
        st.renderer.con_init(u32::from(cols), u32::from(rows));
        let fg = st.fg as usize;
        if !st.graphics[fg] {
            if let Some(cell) = st.vc_cons[fg].as_mut() {
                vtdata::switch(&mut cell.vc, &mut st.renderer);
                DIRTY.store(true, Ordering::Release);
                repaint = true;
            }
        }
    }
    softirq::set_handler(softirq::Slot::FbconFlush, flush_softirq);
    FLUSH_FN.store(flush as *mut (), Ordering::Release);
    publish_geometry(rows, cols, yres.min(u32::from(u16::MAX)) as u16);
    if repaint { queue_flush(); }
    true
}

/// Convert a scanout's visible pixel extent into the active font's text grid.
/// # C: O(1)
fn text_geometry(xres: u32, yres: u32) -> (u16, u16) {
    let font = crate::font::active();
    let (cell_w, cell_h) = (font.width.max(1), font.height.max(1));
    ((xres / cell_w).max(1) as u16, (yres / cell_h).max(1) as u16)
}

pub fn kernel_unregister() {
    READY.store(false, Ordering::Release);
    SUSPENDED.store(false, Ordering::Release);
    DIRTY.store(false, Ordering::Release);
    FLUSH_FN.store(core::ptr::null_mut(), Ordering::Release);
    GEOMETRY_SINK.store(core::ptr::null_mut(), Ordering::Release);
    crate::answerback::clear_sink();
    *lock_vt() = None;
}

pub fn vt_console_sink(bytes: &[u8]) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    if let Some(mut g) = try_lock_vt() {
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
                if !st.graphics[st.fg as usize] {
                    vtdata::render(&mut cell.vc, &mut st.renderer);
                    DIRTY.store(true, Ordering::Release);
                }
                let _ = cell.em.take_reply();
            }
        }
    }
    queue_flush();
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
        let mut guard = lock_vt();
        if let Some(st) = guard.as_mut() {
            let i = st.ensure(vt);
            let is_fg = i == st.fg as usize;
            let may_blit = is_fg && !st.graphics[i];
            if let Some(cell) = st.vc_cons[i].as_mut() {
                cell.em.feed_bytes(&mut cell.vc, bytes);
                if may_blit {
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
        queue_flush();
    }
}

pub fn switch_vt(n: u8) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    {
        let mut guard = lock_vt();
        if let Some(st) = guard.as_mut() {
            let i = st.ensure(n);
            st.fg = i as u8;
            if st.graphics[i] {
                return;
            }
            if let Some(cell) = st.vc_cons[i].as_mut() {
                vtdata::switch(&mut cell.vc, &mut st.renderer);
                DIRTY.store(true, Ordering::Release);
            }
        }
    }
    queue_flush();
}

pub fn set_vt_graphics_mode(n: u8, graphics: bool) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    let mut repaint = false;
    {
        let mut guard = lock_vt();
        if let Some(st) = guard.as_mut() {
            let i = st.ensure(n);
            st.graphics[i] = graphics;
            if i == st.fg as usize && !graphics {
                if let Some(cell) = st.vc_cons[i].as_mut() {
                    vtdata::switch(&mut cell.vc, &mut st.renderer);
                    DIRTY.store(true, Ordering::Release);
                    repaint = true;
                }
            }
        }
    }
    if repaint {
        queue_flush();
    }
}

/// Flush the visible console and prevent later writers from queueing
/// framebuffer softirq work until [`console_resume`].  Writers continue to
/// update the retained VT image, so no text is lost while device callbacks and
/// secondary CPUs are quiesced.  Mirrors Linux `console_suspend_all()`.
/// # C: O(damaged region + NR_CPUS)
/// # Sleeps: no
pub fn console_suspend() {
    SUSPENDED.store(true, Ordering::Release);
    {
        // This acquisition waits for any handler that passed the suspended
        // check before publication, then consumes every damage record that
        // existed before the lifecycle boundary.
        let mut state = lock_vt();
        super::shared::blit_for_suspend(state.as_mut());
    }
    // Producers now observe SUSPENDED and the VT lock synchronized any
    // already-running handler, so stale wake publications can be cancelled.
    softirq::clear_pending(softirq::Slot::FbconFlush);
}

/// Re-enable deferred framebuffer output and publish accumulated damage once.
/// # C: O(1)
pub fn console_resume() {
    SUSPENDED.store(false, Ordering::Release);
    if DIRTY.load(Ordering::Acquire) { queue_flush(); }
}
