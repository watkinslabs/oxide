use core::sync::atomic::Ordering;
use vtdata::Emulator;

use crate::kernel::shared::{lock_vt, try_lock_vt, DIRTY, READY};

pub fn console_dims() -> Option<(u16, u16)> {
    lock_vt().as_ref().map(|st| (st.rows, st.cols))
}

pub fn force_repaint() {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    {
        let mut guard = lock_vt();
        if let Some(st) = guard.as_mut() {
            let fg = st.fg as usize;
            if st.graphics[fg] {
                return;
            }
            if let Some(cell) = st.vc_cons[fg].as_mut() {
                vtdata::switch(&mut cell.vc, &mut st.renderer);
                DIRTY.store(true, Ordering::Release);
            }
        }
    }
    softirq::raise(softirq::Slot::FbconFlush);
}

pub fn scrolldelta(lines: isize) {
    if !READY.load(Ordering::Acquire) || lines == 0 {
        return;
    }
    {
        let mut guard = lock_vt();
        if let Some(st) = guard.as_mut() {
            let fg = st.fg as usize;
            if st.graphics[fg] {
                return;
            }
            if let Some(cell) = st.vc_cons[fg].as_mut() {
                if lines > 0 {
                    cell.vc.scroll_view_up(lines as usize);
                } else {
                    cell.vc.scroll_view_down((-lines) as usize);
                }
                vtdata::switch(&mut cell.vc, &mut st.renderer);
                DIRTY.store(true, Ordering::Release);
            }
        }
    }
    softirq::raise(softirq::Slot::FbconFlush);
}

pub fn screen_dump(with_attr: bool) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    let guard = lock_vt();
    let st = match guard.as_ref() {
        Some(s) => s,
        None => return out,
    };
    let fg = st.fg as usize;
    let cell = match st.vc_cons[fg].as_ref() {
        Some(c) => c,
        None => return out,
    };
    let (rows, cols) = (st.rows, st.cols);
    if with_attr {
        out.push(rows.min(255) as u8);
        out.push(cols.min(255) as u8);
        out.push(cell.vc.x.min(255) as u8);
        out.push(cell.vc.y.min(255) as u8);
    }
    for r in 0..rows {
        for c in 0..cols {
            let g = cell.vc.glyph_at(c, r);
            out.push(if (0x20..0x7f).contains(&g) { g as u8 } else { b' ' });
            if with_attr {
                out.push(0x07);
            }
        }
    }
    out
}

pub fn resize_vt(vt: u8, cols: u16, rows: u16) -> bool {
    if !READY.load(Ordering::Acquire) || cols == 0 || rows == 0 {
        return false;
    }
    let mut blitted = false;
    {
        let mut guard = lock_vt();
        let st = match guard.as_mut() {
            Some(s) => s,
            None => return false,
        };
        if cols > st.cols || rows > st.rows {
            return false;
        }
        let i = st.ensure(vt);
        let is_fg = i == st.fg as usize;
        let may_blit = is_fg && !st.graphics[i];
        if let Some(cell) = st.vc_cons[i].as_mut() {
            cell.vc.resize(cols, rows);
            if may_blit {
                vtdata::switch(&mut cell.vc, &mut st.renderer);
                DIRTY.store(true, Ordering::Release);
                blitted = true;
            }
        }
    }
    if blitted {
        softirq::raise(softirq::Slot::FbconFlush);
    }
    true
}

pub fn foreground() -> u8 {
    lock_vt().as_ref().map(|st| st.fg).unwrap_or(0)
}

fn fg_em_mode(f: impl Fn(&Emulator) -> bool) -> bool {
    if let Some(mut g) = try_lock_vt() {
        if let Some(st) = g.as_mut() {
            let i = st.ensure(st.fg);
            if let Some(cell) = st.vc_cons[i].as_ref() {
                return f(&cell.em);
            }
        }
    }
    false
}

pub fn fg_app_cursor() -> bool {
    fg_em_mode(|em| em.app_cursor())
}

pub fn fg_bracketed_paste() -> bool {
    fg_em_mode(|em| em.bracketed_paste())
}
