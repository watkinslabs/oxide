use super::*;
use super::tables::free_buf_pages;

use syscall::errno::Errno;

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }
fn enomem() -> i64 { -(Errno::Enomem.as_i32() as i64) }
fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Read one ioctl argument struct, or the negative errno to return.
///
/// The range check lives inside `uaccess::copy_from_user` (Linux's `access_ok`
/// inside `copy_from_user`), so a bad pointer answers `EFAULT` — including the
/// unmapped-but-in-range pointer a bare range check cannot detect.
fn arg_in<T: Copy>(arg: u64) -> Result<T, i64> {
    crate::uarg::read_arg::<T>(arg).map_err(errno)
}

/// Write one ioctl argument struct back, or the negative errno to return.
fn arg_out<T: Copy>(arg: u64, value: T) -> Result<(), i64> {
    crate::uarg::write_arg(arg, value).map_err(errno)
}

pub fn create_dumb(card_id: u32, token: u64, arg: u64) -> i64 {
    let mut req: DrmModeCreateDumb = match arg_in(arg) { Ok(r) => r, Err(e) => return e };
    let pitch = match dumb_pitch(req.width, req.bpp) { Some(p) => p, None => return einval() };
    let size = match dumb_size(pitch, req.height) { Some(s) if s > 0 => s, _ => return einval() };
    let order = order_for_bytes(size);
    // Keep this behind the established boot diagnostic feature: a compositor
    // stalled in CREATE_DUMB otherwise leaves no distinction between the PMM
    // allocation and the DRM table publication steps.
    #[cfg(feature = "debug-desktop")]
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
    #[cfg(feature = "debug-desktop")]
    {
        klog::write_raw(b"[DRMDUMB allocated pa=");
        klog::write_hex_u64(pa);
        klog::write_raw(b"]\n");
    }
    let handle = alloc_dumb_handle();
    TABLES.lock().insert_buf(DumbBuf {
        card_id, handle, owner_token: token, pa, size, order,
        w: req.width, h: req.height, pitch, bpp: req.bpp, refcnt: 1,
        mmap_refs: 0, deleted: false,
    });
    req.handle = handle;
    req.pitch = pitch;
    req.size = size;
    if let Err(e) = arg_out(arg, req) { return e; }
    // Keep the completed ABI result beside the allocation trace.  A caller that
    // stops after CREATE_DUMB needs an unambiguous record that the handle,
    // pitch, and size were published successfully, not merely that PMM found
    // pages for the request.
    #[cfg(feature = "debug-desktop")]
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

pub fn map_dumb(card_id: u32, token: u64, arg: u64) -> i64 {
    let mut req: DrmModeMapDumb = match arg_in(arg) { Ok(r) => r, Err(e) => return e };
    if TABLES.lock().find_buf_owned(card_id, token, req.handle).is_none() { return einval(); }
    req.offset = cookie_for(req.handle);
    if let Err(e) = arg_out(arg, req) { return e; }
    0
}

pub fn destroy_dumb(card_id: u32, token: u64, arg: u64) -> i64 {
    let req: DrmModeDestroyDumb = match arg_in(arg) { Ok(r) => r, Err(e) => return e };
    let freed = {
        let mut t = TABLES.lock();
        match t.close_handle(card_id, token, req.handle) { Ok(freed) => freed, Err(()) => return einval() }
    };
    if let Some((pa, order)) = freed { free_buf_pages(pa, order); }
    0
}

pub fn addfb2(card_id: u32, arg: u64) -> i64 { addfb2_for_token(card_id, 0, arg) }

pub fn addfb2_for_token(card_id: u32, token: u64, arg: u64) -> i64 {
    let mut req: DrmModeFbCmd2 = match arg_in(arg) { Ok(r) => r, Err(e) => return e };
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
        let Some(buf) = t.find_buf_owned(card_id, token, req.handles[0]) else { return einval(); };
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
        if !t.ref_handle_owned(card_id, token, req.handles[0]) { return einval(); }
        t.fbs.push(FbObj {
            card_id, fb_id, owner_token: token, bound: false, w: req.width, h: req.height, pixel_format: req.pixel_format,
            handles: req.handles, pitches: req.pitches, offsets: req.offsets, scanout_res_id: 0,
        });
    }
    req.fb_id = fb_id;
    if let Err(e) = arg_out(arg, req) { return e; }
    0
}

pub fn addfb(card_id: u32, arg: u64) -> i64 { addfb_for_token(card_id, 0, arg) }

pub fn addfb_for_token(card_id: u32, token: u64, arg: u64) -> i64 {
    let mut req: DrmModeFbCmd = match arg_in(arg) { Ok(r) => r, Err(e) => return e };
    if req.width == 0 || req.height == 0 || req.handle == 0 { return einval(); }
    let fourcc = match (req.bpp, req.depth) {
        (32, 24) => DRM_FORMAT_XRGB8888,
        (32, 32) => DRM_FORMAT_ARGB8888,
        _ => return einval(),
    };
    {
        let t = TABLES.lock();
        let Some(buf) = t.find_buf_owned(card_id, token, req.handle) else { return einval(); };
        if !fb_plane_fits_buf(req.width, req.height, fourcc, req.pitch, 0, buf) {
            return einval();
        }
    }
    let fb_id = alloc_fb_id();
    {
        let mut t = TABLES.lock();
        if !t.ref_handle_owned(card_id, token, req.handle) { return einval(); }
        t.fbs.push(FbObj {
            card_id, fb_id, owner_token: token, bound: false, w: req.width, h: req.height, pixel_format: fourcc,
            handles: [req.handle, 0, 0, 0], pitches: [req.pitch, 0, 0, 0], offsets: [0; 4],
            scanout_res_id: 0,
        });
    }
    req.fb_id = fb_id;
    if let Err(e) = arg_out(arg, req) { return e; }
    0
}

pub fn rmfb(card_id: u32, token: u64, arg: u64) -> i64 {
    let fb_id: u32 = match arg_in(arg) { Ok(v) => v, Err(e) => return e };
    let retired = match TABLES.lock().remove_owned_fb(card_id, token, fb_id) { Ok(v) => v, Err(()) => return einval() };
    crate::crtc::detach_fb(card_id, fb_id);
    super::tables::release_fb(card_id, retired);
    0
}

pub fn closefb(card_id: u32, token: u64, arg: u64) -> i64 {
    let req: DrmModeCloseFb = match arg_in(arg) { Ok(r) => r, Err(e) => return e };
    match TABLES.lock().close_fb(card_id, token, req.fb_id) {
        Ok(Some(retired)) => super::tables::release_fb(card_id, retired),
        Ok(None) => {}
        Err(()) => return einval(),
    }
    0
}

pub fn gem_close(card_id: u32, token: u64, arg: u64) -> i64 {
    let req: DrmGemClose = match arg_in(arg) { Ok(r) => r, Err(e) => return e };
    let freed = match TABLES.lock().close_handle(card_id, token, req.handle) { Ok(v) => v, Err(()) => return einval() };
    if let Some((pa, order)) = freed { free_buf_pages(pa, order); }
    0
}

pub fn release_file(card_id: u32, token: u64) {
    let (retired, handles) = {
        let mut t = TABLES.lock();
        let ids = t.owned_fb_ids(card_id, token);
        let mut retired = Vec::new();
        for id in ids {
            if let Ok(Some(fb)) = t.close_fb(card_id, token, id) { retired.push(fb); }
        }
        let handles = t.owned_handles(card_id, token);
        (retired, handles)
    };
    for fb in retired { super::tables::release_fb(card_id, fb); }
    for handle in handles {
        let freed = TABLES.lock().close_handle(card_id, token, handle).ok().flatten();
        if let Some((pa, order)) = freed { free_buf_pages(pa, order); }
    }
}
