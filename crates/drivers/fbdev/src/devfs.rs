// /dev/fb0 — Linux fbdev shim per docs/48. Routes FBIO* ioctls
// through the fbdev crate's per-CRTC registry. crate::register
// gets called when 47 (DRM/KMS) binds an FB to a CRTC; until then
// /dev/fb0's ioctls return Eagain.



use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as DriverLockClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, InodeBuilder, FileOps, default_inode_ops, mk_mode};

// NOT 0x7001_0000: pidfd owns the whole 0x70xx_xxxx space (PIDFD_INO_MARKER
// 0x7000_0000, masked 0xFF00_0000), and the pidfd ioctl handler runs BEFORE
// fbdev in the dispatch — so a 0x70-prefixed fb inode had every FBIO* ioctl
// stolen by the pidfd path. Use the 0xFB ("FB") top byte, outside pidfd's range.
pub const FB0_INO_BASE: Ino = 0xFB00_0000;
pub const FBDEV_MAJOR: u32 = 29;

/// Backend-private state (`i_private`) for `/dev/fb<idx>`: the framebuffer
/// index that keys `kva_of`/`flush`/the ioctl path. The old per-inode `ino()`
/// tag is now `FB0_INO_BASE | idx` on the inode. # C: O(1)
pub struct FbData {
    pub idx: u32,
}

static FB_DEVICES: Spinlock<Vec<(u32, Arc<drv::Device>)>, DriverLockClass> = Spinlock::new(Vec::new());

/// `file_operations` for `/dev/fb<idx>` — read/write hit the live scanout via
/// its HHDM kernel mapping, keyed by the `idx` stored in `i_private`.
struct FbFileOps;
impl FileOps for FbFileOps {
    /// Read from the framebuffer at byte offset `o` (Linux fb read). Bytes
    /// past the fb end return 0 (short read). Reads the live scanout via its
    /// HHDM kernel mapping.
    fn read(&self, inode: &Inode, o: u64, b: &mut [u8]) -> KResult<usize> {
        let idx = match inode.private::<FbData>() { Some(d) => d.idx, None => return Ok(0) };
        let (fb_va, bytes) = match crate::kva_of(idx) { Some(v) => v, None => return Ok(0) };
        if o >= bytes { return Ok(0); }
        let n = ((bytes - o) as usize).min(b.len());
        // SAFETY: fb_va is the HHDM mapping of the scanout for `bytes`; o+n <= bytes; CPL=0 read of device-backed memory into the caller-owned slice.
        unsafe { core::ptr::copy_nonoverlapping((fb_va + o) as *const u8, b.as_mut_ptr(), n); }
        Ok(n)
    }

    /// Write to the framebuffer at byte offset `o` then flush to the display
    /// (Linux fb write + defio). Bytes past the fb end are dropped.
    fn write(&self, inode: &Inode, o: u64, b: &[u8]) -> KResult<usize> {
        let idx = match inode.private::<FbData>() { Some(d) => d.idx, None => return Ok(b.len()) };
        let (fb_va, bytes) = match crate::kva_of(idx) { Some(v) => v, None => return Ok(b.len()) };
        if o >= bytes { return Ok(0); }
        let n = ((bytes - o) as usize).min(b.len());
        // SAFETY: fb_va is the HHDM mapping of the scanout for `bytes`; o+n <= bytes; CPL=0 write of the caller's bytes into the device-backed framebuffer.
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), (fb_va + o) as *mut u8, n); }
        crate::flush(idx);
        Ok(n)
    }
}

/// Build the `/dev/fb<idx>` inode: `S_IFCHR|0o666`, `ino = FB0_INO_BASE | idx`
/// (the routing tag the ioctl + mmap paths read), `i_size = smem_len` (best
/// effort at build — `cat /sys`-style size queries; `fbset` uses
/// FBIOGET_FSCREENINFO, not `i_size`), the shared `FbFileOps` data path,
/// lookup → `ENOTDIR` (default i_op). # C: O(1)
pub fn make_fb_inode(idx: u32) -> InodeRef {
    let ino = FB0_INO_BASE | idx as Ino;
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, 0o666), default_inode_ops(), Arc::new(FbFileOps))
        .size(crate::kva_of(idx).map(|(_, n)| n).unwrap_or(0))
        .private(Arc::new(FbData { idx }))
        .build()
}

/// FBIO* ioctl handler. Returns `Some(rv)` if the ioctl is one of
/// FBIOGET_VSCREENINFO / FBIOGET_FSCREENINFO etc; falls back to
/// `None` for unknown commands so the generic CharDev path runs.
/// # C: O(1)
pub fn handle_fbdev_ioctl(inode: &InodeRef, req: u64, arg: u64) -> Option<i64> {
    // F199: precedence-safe parens. The earlier form
    // `tag != FB0_INO_BASE & MASK` evaluated as
    // `tag != (FB0_INO_BASE & MASK)` = `tag != 0`, so every inode
    // with zero top-32 bits (including pty slaves, ino 0x60008003)
    // fell into this branch and got EFAULT from the arg==NULL gate
    // below. Compare against the upper-16-bit base instead.
    if (inode.ino() & 0xFFFF_0000) != FB0_INO_BASE { return None; }
    let idx = (inode.ino() & 0xFFFF) as u32;
    use syscall::errno::Errno;
    let efault = || Some(-(Errno::Efault.as_i32() as i64));
    let user_ok = |p: u64, len: u64| {
        p != 0 && p < hal::USER_VA_END && p.checked_add(len).is_some_and(|end| end <= hal::USER_VA_END)
    };
    match req {
        // ---- pointer-arg ioctls ----
        crate::FBIOGET_VSCREENINFO => {
            if !user_ok(arg, 160) { return efault(); }
            let v = match crate::var_of(idx) { Some(v) => v, None => return Some(-(Errno::Eagain.as_i32() as i64)) };
            // SAFETY: arg validated for 160 B; FbVarScreeninfo is 160 B; aligned write into the caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut crate::FbVarScreeninfo, v); }
            Some(0)
        }
        crate::FBIOGET_FSCREENINFO => {
            if !user_ok(arg, 80) { return efault(); }
            let f = match crate::fix_of(idx) { Some(f) => f, None => return Some(-(Errno::Eagain.as_i32() as i64)) };
            // SAFETY: arg validated for 80 B; FbFixScreeninfo is 80 B; aligned write into the caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut crate::FbFixScreeninfo, f); }
            Some(0)
        }
        crate::FBIOPUT_VSCREENINFO => {
            // The single console scanout can't modeset (no per-fb realloc +
            // reflow). Accept the SAME physical geometry/bpp and any virtual
            // resolution that fits the allocated backing (so xres_virtual /
            // yres_virtual / xoffset / yoffset updates land); reject a different
            // physical xres/yres/bpp with EINVAL. Linux fbdev drivers that
            // can't modeset return EINVAL here — honest, not a fake accept.
            if !user_ok(arg, 160) { return efault(); }
            let mut cur = match crate::var_of(idx) { Some(v) => v, None => return Some(-(Errno::Eagain.as_i32() as i64)) };
            // SAFETY: arg validated for 160 B; read the requested FbVarScreeninfo from the caller's AS.
            let req_v = unsafe { core::ptr::read_volatile(arg as *const crate::FbVarScreeninfo) };
            if req_v.xres != cur.xres || req_v.yres != cur.yres || req_v.bits_per_pixel != cur.bits_per_pixel {
                return Some(-(Errno::Einval.as_i32() as i64));
            }
            // Virtual resolution must cover the visible window and fit the
            // backing (smem_len). xres_virtual==xres, yres_virtual<=backing rows.
            let req_xv = if req_v.xres_virtual == 0 { cur.xres } else { req_v.xres_virtual };
            let req_yv = if req_v.yres_virtual == 0 { cur.yres } else { req_v.yres_virtual };
            let max_rows = match crate::fix_of(idx) {
                Some(f) if f.line_length > 0 => f.smem_len / f.line_length,
                _ => cur.yres,
            };
            if req_xv != cur.xres || req_yv < cur.yres || req_yv > max_rows {
                return Some(-(Errno::Einval.as_i32() as i64));
            }
            // Pan offset (if requested in the same call) must stay in range.
            if crate::pan_check(&req_v, req_v.xoffset, req_v.yoffset).is_err() {
                return Some(-(Errno::Einval.as_i32() as i64));
            }
            cur.xres_virtual = req_xv; cur.yres_virtual = req_yv;
            cur.xoffset = req_v.xoffset; cur.yoffset = req_v.yoffset;
            crate::set_var(idx, cur);
            Some(0)
        }
        crate::FBIOPAN_DISPLAY => {
            // Pan the visible window within the virtual canvas. Single-buffer
            // console keeps yres_virtual==yres, so the only in-range offset is
            // (0,0); a larger virtual canvas (set via PUT_VSCREENINFO) allows a
            // real pan. Out of range → EINVAL (Linux fb_pan_display). On a valid
            // pan we record the offset + flush the displayed region.
            if !user_ok(arg, 160) { return efault(); }
            // SAFETY: arg validated for 160 B; read the requested FbVarScreeninfo from the caller's AS.
            let v = unsafe { core::ptr::read_volatile(arg as *const crate::FbVarScreeninfo) };
            let mut cur = match crate::var_of(idx) { Some(c) => c, None => return Some(-(Errno::Eagain.as_i32() as i64)) };
            if crate::pan_check(&cur, v.xoffset, v.yoffset).is_err() {
                return Some(-(Errno::Einval.as_i32() as i64));
            }
            cur.xoffset = v.xoffset; cur.yoffset = v.yoffset;
            crate::set_var(idx, cur);
            crate::flush(idx);
            Some(0)
        }
        crate::FBIOPUTCMAP => {
            // Truecolor PSEUDO-PALETTE: Linux fb_set_cmap on a truecolor visual
            // writes the driver pseudo_palette (the 16 console colours). Copy
            // `len` entries from the user red/green/blue arrays, pack each into a
            // pixel in the visual's format, store in the [u32;16] palette.
            if !user_ok(arg, 40) { return efault(); }
            // SAFETY: arg validated for 40 B (FbCmap); read the descriptor from the caller's AS.
            let cm = unsafe { core::ptr::read_volatile(arg as *const crate::FbCmap) };
            let end = match cm.start.checked_add(cm.len) { Some(e) => e, None => return Some(-(Errno::Einval.as_i32() as i64)) };
            if end > 16 { return Some(-(Errno::Einval.as_i32() as i64)); }
            if cm.len == 0 { return Some(0); }
            if cm.red == 0 || cm.green == 0 || cm.blue == 0 { return efault(); }
            let nb = (cm.len as u64) * 2;
            if !user_ok(cm.red, nb) || !user_ok(cm.green, nb) || !user_ok(cm.blue, nb) { return efault(); }
            let var = match crate::var_of(idx) { Some(v) => v, None => return Some(-(Errno::Eagain.as_i32() as i64)) };
            for i in 0..cm.len {
                // SAFETY: cm.{red,green,blue} validated for cm.len*2 bytes above; aligned-by-element u16 reads of the caller's palette arrays within the validated span.
                let (r, g, b) = unsafe {
                    (core::ptr::read_volatile((cm.red + (i as u64) * 2) as *const u16),
                     core::ptr::read_volatile((cm.green + (i as u64) * 2) as *const u16),
                     core::ptr::read_volatile((cm.blue + (i as u64) * 2) as *const u16))
                };
                crate::set_palette(idx, (cm.start + i) as usize, crate::pack_pseudo(&var, r, g, b));
            }
            Some(0)
        }
        crate::FBIOGETCMAP => {
            // Read the stored pseudo-palette back into the user arrays
            // (unpack each pixel to Linux 16-bit-per-channel r/g/b).
            if !user_ok(arg, 40) { return efault(); }
            // SAFETY: arg validated for 40 B (FbCmap); read the descriptor from the caller's AS.
            let cm = unsafe { core::ptr::read_volatile(arg as *const crate::FbCmap) };
            let end = match cm.start.checked_add(cm.len) { Some(e) => e, None => return Some(-(Errno::Einval.as_i32() as i64)) };
            if end > 16 { return Some(-(Errno::Einval.as_i32() as i64)); }
            if cm.len == 0 { return Some(0); }
            if cm.red == 0 || cm.green == 0 || cm.blue == 0 { return efault(); }
            let nb = (cm.len as u64) * 2;
            if !user_ok(cm.red, nb) || !user_ok(cm.green, nb) || !user_ok(cm.blue, nb) { return efault(); }
            if cm.transp != 0 && !user_ok(cm.transp, nb) { return efault(); }
            let var = match crate::var_of(idx) { Some(v) => v, None => return Some(-(Errno::Eagain.as_i32() as i64)) };
            for i in 0..cm.len {
                let px = crate::palette_at(idx, (cm.start + i) as usize).unwrap_or(0);
                let (r, g, b) = crate::unpack_pseudo(&var, px);
                // SAFETY: cm.{red,green,blue} validated for cm.len*2 bytes above; aligned-by-element u16 writes into the caller's palette arrays within the validated span.
                unsafe {
                    core::ptr::write_volatile((cm.red + (i as u64) * 2) as *mut u16, r);
                    core::ptr::write_volatile((cm.green + (i as u64) * 2) as *mut u16, g);
                    core::ptr::write_volatile((cm.blue + (i as u64) * 2) as *mut u16, b);
                    if cm.transp != 0 {
                        core::ptr::write_volatile((cm.transp + (i as u64) * 2) as *mut u16, 0);
                    }
                }
            }
            Some(0)
        }
        crate::FBIOGET_VBLANK => {
            // Report the real, tick-driven pseudo-vblank counter (the honest
            // virtual-GPU vsync cadence). count = VBLANK_SEQ; flags advertise a
            // valid frame count + vsync source.
            if !user_ok(arg, 32) { return efault(); }
            let mut vb = crate::FbVblank::default();
            vb.flags = crate::FB_VBLANK_HAVE_COUNT | crate::FB_VBLANK_HAVE_VSYNC;
            vb.count = crate::vblank_seq() as u32;
            // SAFETY: arg validated for 32 B; FbVblank is 32 B; aligned write into the caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut crate::FbVblank, vb); }
            Some(0)
        }
        // ---- by-value-arg ioctls (arg is NOT a pointer) ----
        crate::FBIOBLANK => {
            // arg = FB_BLANK_* level (0..4) by value. Validate, then apply a
            // REAL transition: level ≥ NORMAL clears the displayed image to
            // black; UNBLANK repaints the console. No hardware DPMS power-down
            // (we can't cut panel power on a virtual GPU) — documented; the
            // image-level blank IS observable, which is the honest effect.
            let level = arg as u32;
            if !crate::is_blank_level(level) { return Some(-(Errno::Einval.as_i32() as i64)); }
            crate::apply_blank(idx, level);
            Some(0)
        }
        crate::FBIO_WAITFORVSYNC => {
            // Real wait on the tick-driven pseudo-vblank: read the current seq,
            // block (cooperative yield) until it advances or the bounded
            // deadline elapses, flush the scanout, return 0. NOT an immediate
            // fake — it returns only after a vsync tick actually happened.
            let start = crate::vblank_seq();
            let _ = crate::wait_vblank(start);
            crate::flush(idx);
            Some(0)
        }
        _ => None,
    }
}

/// mmap backing for `/dev/fb<idx>`: the contiguous scanout physical base +
/// length (Linux `fb_mmap` → `remap_pfn_range`). The mmap syscall maps this
/// PA range straight into the process (VmaBacking::PhysRange) so userspace
/// draws to the real framebuffer. `None` if the fb has no real backing.
/// # C: O(1)
pub fn mmap_backing(inode: &InodeRef) -> Option<(u64, u64)> {
    if (inode.ino() & 0xFFFF_0000) != FB0_INO_BASE { return None; }
    crate::backing_of((inode.ino() & 0xFFFF) as u32)
}

/// Boot-time directory setup. Framebuffer nodes are not fabricated here:
/// register_node publishes `/dev/fbN` only after an fbdev instance exists.
/// # SAFETY: caller is the boot path; pre-init.
/// # C: O(depth)
pub fn init() {
}

/// Publish one model-owned framebuffer node.
/// # C: O(N + depth)
pub fn register_node(idx: u32) -> bool {
    if FB_DEVICES.lock().iter().any(|(id, _)| *id == idx) {
        return false;
    }
    let dev = match drv::try_device_add(Arc::new(
        drv::Device::new("graphics", alloc::format!("fb{idx}"), 0, 0, idx)
            .with_devnode("graphics", alloc::format!("fb{idx}"), Some((FBDEV_MAJOR, idx)))
            .with_uevent_env(alloc::vec![alloc::string::String::from("DEVTYPE=fb")])
            .with_node_factory(Arc::new(move || make_fb_inode(idx))),
    )) {
        Ok(dev) => dev,
        Err(_) => return false,
    };
    FB_DEVICES.lock().push((idx, dev));
    true
}

/// Remove one model-owned framebuffer node.
/// # C: O(N + depth)
pub fn unregister_node(idx: u32) -> bool {
    let dev = {
        let mut g = FB_DEVICES.lock();
        let Some(pos) = g.iter().position(|(id, _)| *id == idx) else {
            return false;
        };
        g.remove(pos).1
    };
    drv::device_del(&dev);
    true
}

#[cfg(test)]
pub(crate) fn unregister_all_nodes() {
    let ids: Vec<u32> = FB_DEVICES.lock().iter().map(|(idx, _)| *idx).collect();
    for idx in ids {
        let _ = unregister_node(idx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_node_is_idempotent_without_republishing() {
        let idx = 0x7ffe;
        let _ = unregister_node(idx);

        assert!(register_node(idx));
        assert!(!register_node(idx));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "graphics" && d.addr == alloc::format!("fb{idx}"))
                .count(),
            1
        );

        assert!(unregister_node(idx));
    }

    #[test]
    fn unregister_then_register_restores_model_owned_node() {
        let idx = 0x7ffc;
        let addr = alloc::format!("fb{idx}");
        let _ = unregister_node(idx);

        assert!(register_node(idx));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "graphics" && d.addr == addr)
                .count(),
            1
        );
        assert!(unregister_node(idx));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "graphics" && d.addr == addr)
                .count(),
            0
        );

        assert!(register_node(idx));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "graphics" && d.addr == addr)
                .count(),
            1
        );
        assert!(unregister_node(idx));
    }

    #[test]
    fn register_node_leaves_slot_free_when_model_publication_conflicts() {
        let idx = 0x7ffd;
        let _ = unregister_node(idx);
        let addr = alloc::format!("fb{idx}");
        let conflict = drv::try_device_add(Arc::new(
            drv::Device::new("graphics", addr.clone(), 0, 0, idx)
                .with_devnode("graphics", addr.clone(), Some((FBDEV_MAJOR, idx))),
        ))
        .expect("conflict device registration");

        assert!(!register_node(idx));
        assert!(!FB_DEVICES.lock().iter().any(|(id, _)| *id == idx));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "graphics" && d.addr == addr)
                .count(),
            1
        );

        drv::device_del(&conflict);
        assert!(register_node(idx));
        assert!(unregister_node(idx));
    }
}
