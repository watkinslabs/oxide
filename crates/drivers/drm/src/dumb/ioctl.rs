use super::*;
use super::tables::free_buf_pages;

use syscall::errno::Errno;

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }
fn enomem() -> i64 { -(Errno::Enomem.as_i32() as i64) }

fn user_ok(ptr: u64, len: u64) -> bool {
    ptr != 0 && ptr < hal::USER_VA_END && ptr.checked_add(len).is_some_and(|end| end <= hal::USER_VA_END)
}

pub fn create_dumb(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeCreateDumb>() as u64) { return einval(); }
    let mut req: DrmModeCreateDumb = unsafe { core::ptr::read_volatile(arg as *const DrmModeCreateDumb) };
    let pitch = match dumb_pitch(req.width, req.bpp) { Some(p) => p, None => return einval() };
    let size = match dumb_size(pitch, req.height) { Some(s) if s > 0 => s, _ => return einval() };
    let order = order_for_bytes(size);
    // Keep this behind the established boot diagnostic feature: a compositor
    // stalled in CREATE_DUMB otherwise leaves no distinction between the PMM
    // allocation and the DRM table publication steps.
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[DRMDUMB begin card=");
        klog::write_dec_u64(card_id as u64);
        klog::write_raw(b" w=");
        klog::write_dec_u64(req.width as u64);
        klog::write_raw(b" h=");
        klog::write_dec_u64(req.height as u64);
        klog::write_raw(b" bpp=");
        klog::write_dec_u64(req.bpp as u64);
        klog::write_raw(b" pitch=");
        klog::write_dec_u64(pitch as u64);
        klog::write_raw(b" size=");
        klog::write_dec_u64(size);
        klog::write_raw(b" order=");
        klog::write_dec_u64(order as u64);
        klog::write_raw(b"]\n");
    }
    let pa = match pmm::setup::alloc_contig_object(pmm::Order(order)) { Some(p) => p, None => return enomem() };
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[DRMDUMB allocated pa=");
        klog::write_hex_u64(pa);
        klog::write_raw(b"]\n");
    }
    let handle = alloc_dumb_handle();
    TABLES.lock().insert_buf(DumbBuf {
        card_id, handle, pa, size, order,
        w: req.width, h: req.height, pitch, bpp: req.bpp, refcnt: 1,
        mmap_refs: 0, deleted: false,
    });
    req.handle = handle;
    req.pitch = pitch;
    req.size = size;
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeCreateDumb, req); }
    // Keep the completed ABI result beside the allocation trace.  A caller that
    // stops after CREATE_DUMB needs an unambiguous record that the handle,
    // pitch, and size were published successfully, not merely that PMM found
    // pages for the request.
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[DRMDUMB ready handle=");
        klog::write_dec_u64(handle as u64);
        klog::write_raw(b" pitch=");
        klog::write_dec_u64(pitch as u64);
        klog::write_raw(b" size=");
        klog::write_dec_u64(size);
        klog::write_raw(b"]\n");
    }
    0
}

pub fn map_dumb(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeMapDumb>() as u64) { return einval(); }
    let mut req: DrmModeMapDumb = unsafe { core::ptr::read_volatile(arg as *const DrmModeMapDumb) };
    if TABLES.lock().find_buf(card_id, req.handle).is_none() { return einval(); }
    req.offset = cookie_for(req.handle);
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeMapDumb, req); }
    0
}

pub fn destroy_dumb(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeDestroyDumb>() as u64) { return einval(); }
    let req: DrmModeDestroyDumb = unsafe { core::ptr::read_volatile(arg as *const DrmModeDestroyDumb) };
    let freed = {
        let mut t = TABLES.lock();
        if t.find_buf(card_id, req.handle).is_none() { return einval(); }
        t.unref_handle(card_id, req.handle)
    };
    if let Some((pa, order)) = freed { free_buf_pages(pa, order); }
    0
}

pub fn addfb2(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeFbCmd2>() as u64) { return einval(); }
    let mut req: DrmModeFbCmd2 = unsafe { core::ptr::read_volatile(arg as *const DrmModeFbCmd2) };
    // Accept the explicit-modifier path (DRM_MODE_FB_MODIFIERS) now that IN_FORMATS
    // advertises the LINEAR modifier: mutter may pass flags=DRM_MODE_FB_MODIFIERS
    // with modifier[0]=LINEAR(0) or INVALID ("driver picks", = linear for our
    // PMM-contiguous dumb buffers). Reject any other flag (INTERLACED) or a
    // non-linear/tiled modifier we cannot honor. Modifiers are only meaningful
    // when the flag is set.
    const DRM_MODE_FB_MODIFIERS: u32 = 0x2;
    const DRM_FORMAT_MOD_INVALID: u64 = 0x00ff_ffff_ffff_ffff;
    if req.flags & !DRM_MODE_FB_MODIFIERS != 0 { return einval(); }
    if req.flags & DRM_MODE_FB_MODIFIERS != 0 {
        if req.modifier[0] != 0 && req.modifier[0] != DRM_FORMAT_MOD_INVALID { return einval(); }
        if req.modifier[1..].iter().any(|m| *m != 0) { return einval(); }
    }
    if !format_supported(req.pixel_format) { return einval(); }
    if req.width == 0 || req.height == 0 { return einval(); }
    if req.handles[0] == 0 { return einval(); }
    if req.handles[1..].iter().any(|h| *h != 0) { return einval(); }
    if req.pitches[1..].iter().any(|p| *p != 0) { return einval(); }
    if req.offsets[1..].iter().any(|o| *o != 0) { return einval(); }
    {
        let t = TABLES.lock();
        let Some(buf) = t.find_buf(card_id, req.handles[0]) else { return einval(); };
        if !fb_plane_fits_buf(
            req.width,
            req.height,
            req.pixel_format,
            req.pitches[0],
            req.offsets[0],
            buf,
        ) {
            return einval();
        }
    }
    let fb_id = alloc_fb_id();
    {
        let mut t = TABLES.lock();
        t.ref_handle(card_id, req.handles[0]);
        t.fbs.push(FbObj {
            card_id, fb_id, w: req.width, h: req.height, pixel_format: req.pixel_format,
            handles: req.handles, pitches: req.pitches, offsets: req.offsets, scanout_res_id: 0,
        });
    }
    req.fb_id = fb_id;
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeFbCmd2, req); }
    0
}

pub fn addfb(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeFbCmd>() as u64) { return einval(); }
    let mut req: DrmModeFbCmd = unsafe { core::ptr::read_volatile(arg as *const DrmModeFbCmd) };
    if req.width == 0 || req.height == 0 || req.handle == 0 { return einval(); }
    let fourcc = match (req.bpp, req.depth) {
        (32, 24) => DRM_FORMAT_XRGB8888,
        (32, 32) => DRM_FORMAT_ARGB8888,
        _ => return einval(),
    };
    {
        let t = TABLES.lock();
        let Some(buf) = t.find_buf(card_id, req.handle) else { return einval(); };
        if !fb_plane_fits_buf(req.width, req.height, fourcc, req.pitch, 0, buf) {
            return einval();
        }
    }
    let fb_id = alloc_fb_id();
    {
        let mut t = TABLES.lock();
        t.ref_handle(card_id, req.handle);
        t.fbs.push(FbObj {
            card_id, fb_id, w: req.width, h: req.height, pixel_format: fourcc,
            handles: [req.handle, 0, 0, 0], pitches: [req.pitch, 0, 0, 0], offsets: [0; 4],
            scanout_res_id: 0,
        });
    }
    req.fb_id = fb_id;
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeFbCmd, req); }
    0
}

pub fn rmfb(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, 4) { return einval(); }
    let fb_id: u32 = unsafe { core::ptr::read_volatile(arg as *const u32) };
    let (to_free, scanout_res_id) = {
        let mut t = TABLES.lock();
        let idx = match t.fbs.iter().position(|f| f.card_id == card_id && f.fb_id == fb_id) { Some(i) => i, None => return einval() };
        let fb = t.fbs.remove(idx);
        let scanout_res_id = fb.scanout_res_id;
        let mut freed: [Option<(u64, u8)>; 4] = [None; 4];
        for (i, &h) in fb.handles.iter().enumerate() {
            if h != 0 { freed[i] = t.unref_handle(card_id, h); }
        }
        (freed, scanout_res_id)
    };
    crate::crtc::detach_fb(card_id, fb_id);
    release_scanout_resource(card_id, scanout_res_id);
    for f in to_free.iter().flatten() { free_buf_pages(f.0, f.1); }
    0
}
