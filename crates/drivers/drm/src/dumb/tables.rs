use super::*;
use super::math::DUMB_PAGE_SIZE;

#[derive(Copy, Clone, Debug)]
pub struct DumbBuf {
    pub card_id: u32,
    pub handle: u32,
    pub owner_token: u64,
    pub pa: u64,
    pub size: u64,
    pub order: u8,
    pub w: u32,
    pub h: u32,
    pub pitch: u32,
    pub bpp: u32,
    pub refcnt: u32,
    pub mmap_refs: u32,
    pub deleted: bool,
}

#[derive(Copy, Clone, Debug)]
pub struct FbObj {
    pub card_id: u32,
    pub fb_id: u32,
    pub owner_token: u64,
    pub bound: bool,
    pub w: u32,
    pub h: u32,
    pub pixel_format: u32,
    pub handles: [u32; 4],
    pub pitches: [u32; 4],
    pub offsets: [u32; 4],
    pub scanout_res_id: u32,
}

pub struct DumbTables {
    pub bufs: Vec<DumbBuf>,
    pub fbs: Vec<FbObj>,
}

impl DumbTables {
    pub const fn new() -> Self { Self { bufs: Vec::new(), fbs: Vec::new() } }

    pub fn insert_buf(&mut self, b: DumbBuf) { self.bufs.push(b); }

    pub fn find_buf(&self, card_id: u32, h: u32) -> Option<&DumbBuf> {
        self.bufs.iter().find(|b| b.card_id == card_id && b.handle == h && !b.deleted)
    }

    pub fn find_buf_owned(&self, card_id: u32, token: u64, h: u32) -> Option<&DumbBuf> {
        self.bufs.iter().find(|b| b.card_id == card_id && b.handle == h
            && b.owner_token == token && !b.deleted)
    }

    pub fn find_buf_object(&self, card_id: u32, h: u32) -> Option<&DumbBuf> {
        self.bufs.iter().find(|b| b.card_id == card_id && b.handle == h)
    }

    fn find_buf_mut(&mut self, card_id: u32, h: u32) -> Option<&mut DumbBuf> {
        self.bufs.iter_mut().find(|b| b.card_id == card_id && b.handle == h && !b.deleted)
    }

    fn find_buf_object_mut(&mut self, card_id: u32, h: u32) -> Option<&mut DumbBuf> {
        self.bufs.iter_mut().find(|b| b.card_id == card_id && b.handle == h)
    }

    pub fn find_fb(&self, card_id: u32, id: u32) -> Option<&FbObj> {
        self.fbs.iter().find(|f| f.card_id == card_id && f.fb_id == id)
    }

    pub fn find_fb_mut(&mut self, card_id: u32, id: u32) -> Option<&mut FbObj> {
        self.fbs.iter_mut().find(|f| f.card_id == card_id && f.fb_id == id)
    }

    pub fn owns_fb(&self, card_id: u32, token: u64, id: u32) -> bool {
        self.fbs.iter().any(|f| f.card_id == card_id && f.fb_id == id
            && f.owner_token == token)
    }

    pub fn ref_handle(&mut self, card_id: u32, h: u32) -> bool {
        match self.find_buf_mut(card_id, h) { Some(b) => { b.refcnt += 1; true } None => false }
    }

    pub fn ref_handle_owned(&mut self, card_id: u32, token: u64, h: u32) -> bool {
        match self.bufs.iter_mut().find(|b| b.card_id == card_id && b.handle == h
            && b.owner_token == token && !b.deleted) {
            Some(b) => { b.refcnt += 1; true }
            None => false,
        }
    }

    pub fn unref_handle(&mut self, card_id: u32, h: u32) -> Option<(u64, u8)> {
        let idx = self.bufs.iter().position(|b| b.card_id == card_id && b.handle == h)?;
        if self.bufs[idx].refcnt > 0 { self.bufs[idx].refcnt -= 1; }
        if self.bufs[idx].refcnt == 0 {
            let b = self.bufs.remove(idx);
            Some((b.pa, b.order))
        } else {
            None
        }
    }

    pub fn close_handle(&mut self, card_id: u32, token: u64, h: u32)
        -> Result<Option<(u64, u8)>, ()> {
        let Some(b) = self.find_buf_object_mut(card_id, h) else { return Err(()) };
        if b.deleted || b.owner_token != token { return Err(()); }
        b.deleted = true;
        b.owner_token = 0;
        Ok(self.unref_handle(card_id, h))
    }

    fn retire_fb_at(&mut self, idx: usize) -> ([Option<(u64, u8)>; 4], u32) {
        let fb = self.fbs.remove(idx);
        let mut freed = [None; 4];
        for (slot, &h) in fb.handles.iter().enumerate() {
            if h != 0 { freed[slot] = self.unref_handle(fb.card_id, h); }
        }
        (freed, fb.scanout_res_id)
    }

    pub fn close_fb(&mut self, card_id: u32, token: u64, fb_id: u32)
        -> Result<Option<([Option<(u64, u8)>; 4], u32)>, ()> {
        let Some(idx) = self.fbs.iter().position(|f| f.card_id == card_id
            && f.fb_id == fb_id && f.owner_token == token) else { return Err(()) };
        self.fbs[idx].owner_token = 0;
        if self.fbs[idx].bound { Ok(None) } else { Ok(Some(self.retire_fb_at(idx))) }
    }

    pub fn remove_owned_fb(&mut self, card_id: u32, token: u64, fb_id: u32)
        -> Result<([Option<(u64, u8)>; 4], u32), ()> {
        let Some(idx) = self.fbs.iter().position(|f| f.card_id == card_id
            && f.fb_id == fb_id && f.owner_token == token) else { return Err(()) };
        Ok(self.retire_fb_at(idx))
    }

    pub fn replace_bound_fb(&mut self, card_id: u32, old_id: u32, new_id: u32)
        -> Option<([Option<(u64, u8)>; 4], u32)> {
        if old_id == new_id { return None; }
        if new_id != 0 {
            if let Some(fb) = self.find_fb_mut(card_id, new_id) { fb.bound = true; }
        }
        if old_id == 0 { return None; }
        let idx = self.fbs.iter().position(|f| f.card_id == card_id && f.fb_id == old_id)?;
        self.fbs[idx].bound = false;
        if self.fbs[idx].owner_token == 0 { Some(self.retire_fb_at(idx)) } else { None }
    }

    pub fn owned_fb_ids(&self, card_id: u32, token: u64) -> Vec<u32> {
        self.fbs.iter().filter(|f| f.card_id == card_id && f.owner_token == token)
            .map(|f| f.fb_id).collect()
    }

    pub fn owned_handles(&self, card_id: u32, token: u64) -> Vec<u32> {
        self.bufs.iter().filter(|b| b.card_id == card_id && b.owner_token == token
            && !b.deleted).map(|b| b.handle).collect()
    }

    pub fn pin_mmap(&mut self, card_id: u32, h: u32) -> Option<DumbMmapPin> {
        let b = self.find_buf_mut(card_id, h)?;
        b.refcnt = b.refcnt.saturating_add(1);
        b.mmap_refs = b.mmap_refs.saturating_add(1);
        Some(DumbMmapPin { card_id, handle: h, pa: b.pa, size: b.size })
    }

    pub fn pin_mmap_owned(&mut self, card_id: u32, token: u64, h: u32) -> Option<DumbMmapPin> {
        if self.find_buf_owned(card_id, token, h).is_none() { return None; }
        self.pin_mmap(card_id, h)
    }

    pub fn unpin_mmap(&mut self, card_id: u32, h: u32) -> Option<(u64, u8)> {
        let idx = self.bufs.iter().position(|b| b.card_id == card_id && b.handle == h)?;
        if self.bufs[idx].mmap_refs > 0 { self.bufs[idx].mmap_refs -= 1; }
        if self.bufs[idx].refcnt > 0 { self.bufs[idx].refcnt -= 1; }
        if self.bufs[idx].refcnt == 0 {
            let b = self.bufs.remove(idx);
            Some((b.pa, b.order))
        } else {
            None
        }
    }

    pub fn remove_card(&mut self, card_id: u32) -> (Vec<(u64, u8)>, Vec<u32>) {
        let mut freed = Vec::new();
        let mut resources = Vec::new();
        let mut fb_idx = 0usize;
        while fb_idx < self.fbs.len() {
            if self.fbs[fb_idx].card_id != card_id {
                fb_idx += 1;
                continue;
            }
            let fb = self.fbs.remove(fb_idx);
            if fb.scanout_res_id != 0 {
                resources.push(fb.scanout_res_id);
            }
            for &h in &fb.handles {
                if h != 0 {
                    if let Some(f) = self.unref_handle(card_id, h) { freed.push(f); }
                }
            }
        }
        let mut idx = 0usize;
        while idx < self.bufs.len() {
            if self.bufs[idx].card_id == card_id {
                self.bufs[idx].deleted = true;
                let non_mmap_refs = self.bufs[idx].refcnt.saturating_sub(self.bufs[idx].mmap_refs);
                self.bufs[idx].refcnt = self.bufs[idx].refcnt.saturating_sub(non_mmap_refs);
                if self.bufs[idx].refcnt == 0 {
                    let b = self.bufs.remove(idx);
                    freed.push((b.pa, b.order));
                } else {
                    idx += 1;
                }
            } else {
                idx += 1;
            }
        }
        (freed, resources)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DumbMmapPin {
    pub card_id: u32,
    pub handle: u32,
    pub pa: u64,
    pub size: u64,
}

pub static TABLES: Spinlock<DumbTables, DumbLockClass> = Spinlock::new(DumbTables::new());
static NEXT_DUMB_HANDLE: AtomicU32 = AtomicU32::new(1);
static NEXT_FB_ID: AtomicU32 = AtomicU32::new(1);

pub fn alloc_dumb_handle() -> u32 { NEXT_DUMB_HANDLE.fetch_add(1, Ordering::AcqRel) }
pub fn alloc_fb_id() -> u32 { NEXT_FB_ID.fetch_add(1, Ordering::AcqRel) }

pub(super) fn release_scanout_resource(card_id: u32, res_id: u32) {
    if res_id == 0 {
        return;
    }
    if let Some(ops) = crate::node::scanout_ops(card_id) {
        let _ = (ops.destroy_resource)(ops.driver_key, res_id);
    }
}

pub(super) fn release_fb(card_id: u32, retired: ([Option<(u64, u8)>; 4], u32)) {
    release_scanout_resource(card_id, retired.1);
    for (pa, order) in retired.0.into_iter().flatten() { free_buf_pages(pa, order); }
}

pub fn replace_bound_fb(card_id: u32, old_id: u32, new_id: u32) {
    let retired = TABLES.lock().replace_bound_fb(card_id, old_id, new_id);
    if let Some(retired) = retired { release_fb(card_id, retired); }
}

pub fn bind_fb_scanout_resource(card_id: u32, fb_id: u32, res_id: u32) -> bool {
    if res_id == 0 {
        return false;
    }
    let mut t = TABLES.lock();
    let Some(fb) = t.find_fb_mut(card_id, fb_id) else {
        return false;
    };
    if fb.scanout_res_id != 0 {
        return false;
    }
    fb.scanout_res_id = res_id;
    true
}

pub(super) fn free_buf_pages(pa: u64, order: u8) {
    // Reached only from `close_handle` handing back the run after the LAST
    // handle and mmap reference went away.
    // SAFETY: `pa`/`order` name the `alloc_contig_object` run this dumb buffer
    // was created with, and the per-frame drop frees only at refcount zero, so a
    // still-mapped VMA — which holds one object ref per page — keeps its page.
    unsafe {
        let frames = 1u64 << order;
        for i in 0..frames {
            pmm::setup::dec_object_ref_and_maybe_free_frame(pa + i * DUMB_PAGE_SIZE);
        }
    }
}

pub fn pin_mmap(card_id: u32, cookie: u64) -> Option<DumbMmapPin> {
    let h = handle_of_cookie(cookie)?;
    TABLES.lock().pin_mmap(card_id, h)
}

pub fn unpin_mmap(pin: DumbMmapPin) {
    let freed = TABLES.lock().unpin_mmap(pin.card_id, pin.handle);
    if let Some((pa, order)) = freed { free_buf_pages(pa, order); }
}

/// Snapshot a 32-bit dumb buffer suitable for a tightly-packed cursor
/// resource. The caller retains it with `ref_cursor_handle` before issuing a
/// device command, so a concurrently closed DRM handle cannot free its pages.
/// # C: O(n) over the card's dumb table.
pub fn cursor_source(card_id: u32, token: u64, handle: u32) -> Option<(u64, u32, u32, u32)> {
    let t = TABLES.lock();
    let b = t.find_buf_owned(card_id, token, handle)?;
    Some((b.pa, b.w, b.h, b.pitch))
}

/// Hold a dumb handle while it is bound as the card cursor. # C: O(n)
pub fn ref_cursor_handle(card_id: u32, token: u64, handle: u32) -> bool {
    TABLES.lock().ref_handle_owned(card_id, token, handle)
}

/// Drop the cursor's ownership reference and free the pages if it was last.
/// # C: O(n)
pub fn unref_cursor_handle(card_id: u32, handle: u32) {
    if let Some((pa, order)) = TABLES.lock().unref_handle(card_id, handle) {
        free_buf_pages(pa, order);
    }
}

pub fn mmap_backing(card_id: u32, cookie: u64) -> Option<(u64, u64)> {
    let h = handle_of_cookie(cookie)?;
    let t = TABLES.lock();
    let b = t.find_buf(card_id, h)?;
    Some((b.pa, b.size))
}

pub fn clear_card_state(card_id: u32) {
    let (freed, resources) = TABLES.lock().remove_card(card_id);
    for res_id in resources {
        release_scanout_resource(card_id, res_id);
    }
    for (pa, order) in freed { free_buf_pages(pa, order); }
}
