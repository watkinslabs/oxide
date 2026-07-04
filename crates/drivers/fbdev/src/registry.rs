use super::*;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Inval, Again, Busy, IoErr, Perm }

pub type KResult<T> = core::result::Result<T, Error>;

pub struct FbDev {
    pub idx: u32,
    pub var: FbVarScreeninfo,
    pub fix: FbFixScreeninfo,
    pub base_pa: u64,
    pub fb_va: u64,
    pub fb_bytes: u64,
    pub card_id: u32,
    pub crtc_id: u32,
    pub fb_id: u32,
    pub dumb_handle: u32,
    pub blank: u32,
    pub pseudo_palette: [u32; 16],
    pub ops: Option<FbOps>,
}

pub static FBS: Spinlock<Vec<FbDev>, DriverLockClass> = Spinlock::new(Vec::new());

#[derive(Copy, Clone)]
pub struct FbOps {
    pub driver_key: u32,
    pub flush: fn(u32),
    pub blank: fn(u32),
    pub unblank: fn(u32),
}

pub const INVALID_FB_INDEX: u32 = u32::MAX;

fn lowest_free_fb_idx(fbs: &[FbDev]) -> u32 {
    let mut idx = 0u32;
    loop {
        if fbs.iter().all(|f| f.idx != idx) {
            return idx;
        }
        idx = idx.saturating_add(1);
    }
}

fn publish_or_unwind(idx: u32) -> Option<u32> {
    #[cfg(target_os = "oxide-kernel")]
    if !devfs::register_node(idx) {
        let mut g = FBS.lock();
        if let Some(pos) = g.iter().position(|f| f.idx == idx) {
            g.remove(pos);
        }
        return None;
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = idx;
    Some(idx)
}

pub fn set_ops(idx: u32, ops: FbOps) -> bool {
    let mut g = FBS.lock();
    let Some(fb) = g.iter_mut().find(|f| f.idx == idx) else { return false };
    fb.ops = Some(ops);
    true
}

pub fn clear_ops(idx: u32) -> bool {
    let mut g = FBS.lock();
    let Some(fb) = g.iter_mut().find(|f| f.idx == idx) else { return false };
    fb.ops = None;
    true
}

pub(super) fn ops_of(idx: u32) -> Option<FbOps> {
    FBS.lock().iter().find(|f| f.idx == idx).and_then(|f| f.ops)
}

pub fn flush(idx: u32) {
    if let Some(ops) = ops_of(idx) {
        (ops.flush)(ops.driver_key);
    }
}

pub fn pan_check(v: &FbVarScreeninfo, xoffset: u32, yoffset: u32) -> KResult<()> {
    let xr = xoffset.checked_add(v.xres).ok_or(Error::Inval)?;
    let yr = yoffset.checked_add(v.yres).ok_or(Error::Inval)?;
    if xr <= v.xres_virtual && yr <= v.yres_virtual { Ok(()) } else { Err(Error::Inval) }
}

pub fn pack_pseudo(v: &FbVarScreeninfo, r16: u16, g16: u16, b16: u16) -> u32 {
    let chan = |val16: u16, bf: &FbBitfield| -> u32 {
        if bf.length == 0 { return 0; }
        let v = (val16 as u32) >> (16 - bf.length);
        (v & ((1u32 << bf.length) - 1)) << bf.offset
    };
    chan(r16, &v.red) | chan(g16, &v.green) | chan(b16, &v.blue)
}

pub fn unpack_pseudo(v: &FbVarScreeninfo, px: u32) -> (u16, u16, u16) {
    let chan = |bf: &FbBitfield| -> u16 {
        if bf.length == 0 { return 0; }
        let raw = (px >> bf.offset) & ((1u32 << bf.length) - 1);
        let mut out = 0u32;
        let mut filled = 0u32;
        while filled < 16 {
            let shift = 16i32 - filled as i32 - bf.length as i32;
            if shift >= 0 { out |= raw << shift; } else { out |= raw >> (-shift); }
            filled += bf.length;
        }
        (out & 0xFFFF) as u16
    };
    (chan(&v.red), chan(&v.green), chan(&v.blue))
}

pub fn init_scanout(base_pa: u64, fb_va: u64, fb_bytes: u64, pitch: u32, w: u32, h: u32) -> u32 {
    let mut var = FbVarScreeninfo::default();
    var.xres = w;
    var.yres = h;
    var.xres_virtual = w;
    var.yres_virtual = h;
    let mut fix = FbFixScreeninfo::default();
    fix.smem_start = base_pa;
    fix.smem_len = fb_bytes as u32;
    fix.line_length = pitch;
    let idx = {
        let mut g = FBS.lock();
        let idx = lowest_free_fb_idx(&g);
        g.push(FbDev {
            idx,
            var,
            fix,
            base_pa,
            fb_va,
            fb_bytes,
            card_id: 0,
            crtc_id: 0,
            fb_id: 0,
            dumb_handle: 0,
            blank: FB_BLANK_UNBLANK,
            pseudo_palette: [0; 16],
            ops: None,
        });
        idx
    };
    publish_or_unwind(idx).unwrap_or(INVALID_FB_INDEX)
}

pub fn unregister(idx: u32) -> bool {
    #[cfg(target_os = "oxide-kernel")]
    let _ = devfs::unregister_node(idx);
    let mut g = FBS.lock();
    let Some(pos) = g.iter().position(|f| f.idx == idx) else { return false };
    g.remove(pos);
    true
}

pub fn unregister_by_base(base_pa: u64) -> bool {
    let idx = {
        let g = FBS.lock();
        let Some(fb) = g.iter().find(|f| f.base_pa == base_pa) else { return false };
        fb.idx
    };
    unregister(idx)
}

pub fn backing_of(idx: u32) -> Option<(u64, u64)> {
    FBS.lock().iter().find(|f| f.idx == idx && f.base_pa != 0).map(|f| (f.base_pa, f.fb_bytes))
}

pub fn kva_of(idx: u32) -> Option<(u64, u64)> {
    FBS.lock().iter().find(|f| f.idx == idx && f.fb_va != 0).map(|f| (f.fb_va, f.fb_bytes))
}

pub fn register(card_id: u32, crtc_id: u32, var: FbVarScreeninfo, fix: FbFixScreeninfo) -> u32 {
    let idx = {
        let mut g = FBS.lock();
        let idx = lowest_free_fb_idx(&g);
        g.push(FbDev {
            idx,
            var,
            fix,
            base_pa: 0,
            fb_va: 0,
            fb_bytes: 0,
            card_id,
            crtc_id,
            fb_id: 0,
            dumb_handle: 0,
            blank: FB_BLANK_UNBLANK,
            pseudo_palette: [0; 16],
            ops: None,
        });
        idx
    };
    publish_or_unwind(idx).unwrap_or(INVALID_FB_INDEX)
}

pub fn count() -> usize { FBS.lock().len() }

pub fn var_of(idx: u32) -> Option<FbVarScreeninfo> {
    FBS.lock().iter().find(|f| f.idx == idx).map(|f| f.var)
}

pub fn set_var(idx: u32, var: FbVarScreeninfo) {
    if let Some(f) = FBS.lock().iter_mut().find(|f| f.idx == idx) { f.var = var; }
}

pub fn fix_of(idx: u32) -> Option<FbFixScreeninfo> {
    FBS.lock().iter().find(|f| f.idx == idx).map(|f| f.fix)
}

pub fn line_length(xres: u32, bpp: u32) -> u32 {
    let raw = xres.saturating_mul(bpp / 8);
    (raw + 63) & !63
}

pub fn is_blank_level(level: u32) -> bool { level <= FB_BLANK_POWERDOWN }

pub fn blank_of(idx: u32) -> Option<u32> {
    FBS.lock().iter().find(|f| f.idx == idx).map(|f| f.blank)
}

pub fn set_blank(idx: u32, level: u32) {
    if let Some(f) = FBS.lock().iter_mut().find(|f| f.idx == idx) { f.blank = level; }
}

pub fn set_palette(idx: u32, i: usize, entry: u32) {
    if i >= 16 { return; }
    if let Some(f) = FBS.lock().iter_mut().find(|f| f.idx == idx) { f.pseudo_palette[i] = entry; }
}

pub fn palette_at(idx: u32, i: usize) -> Option<u32> {
    if i >= 16 { return None; }
    FBS.lock().iter().find(|f| f.idx == idx).map(|f| f.pseudo_palette[i])
}

pub fn apply_blank(idx: u32, level: u32) {
    let prev = blank_of(idx).unwrap_or(FB_BLANK_UNBLANK);
    set_blank(idx, level);
    let ops = ops_of(idx);
    if level == FB_BLANK_UNBLANK {
        if prev != FB_BLANK_UNBLANK {
            if let Some(ops) = ops {
                (ops.unblank)(ops.driver_key);
            }
        }
    } else if let Some(ops) = ops {
        (ops.blank)(ops.driver_key);
    }
}
