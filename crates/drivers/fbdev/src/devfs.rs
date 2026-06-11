// /dev/fb0 — Linux fbdev shim per docs/48. Routes FBIO* ioctls
// through the fbdev crate's per-CRTC registry. crate::register
// gets called when 47 (DRM/KMS) binds an FB to a CRTC; until then
// /dev/fb0's ioctls return Eagain.



use alloc::sync::Arc;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

pub const FB0_INO_BASE: Ino = 0x7001_0000;

pub struct FbInode {
    pub idx: u32,
}

impl Inode for FbInode {
    fn ino(&self) -> Ino { FB0_INO_BASE | self.idx as u64 }
    fn file_type(&self) -> FileType { FileType::CharDev }
    /// smem_len — `cat /sys`-style size queries + `fbset` use it.
    fn size(&self) -> u64 { crate::kva_of(self.idx).map(|(_, n)| n).unwrap_or(0) }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }

    /// Read from the framebuffer at byte offset `o` (Linux fb read). Bytes
    /// past the fb end return 0 (short read). Reads the live scanout via its
    /// HHDM kernel mapping.
    fn read(&self, o: u64, b: &mut [u8]) -> KResult<usize> {
        let (fb_va, bytes) = match crate::kva_of(self.idx) { Some(v) => v, None => return Ok(0) };
        if o >= bytes { return Ok(0); }
        let n = ((bytes - o) as usize).min(b.len());
        // SAFETY: fb_va is the HHDM mapping of the scanout for `bytes`; o+n <= bytes; CPL=0 read of device-backed memory into the caller-owned slice.
        unsafe { core::ptr::copy_nonoverlapping((fb_va + o) as *const u8, b.as_mut_ptr(), n); }
        Ok(n)
    }

    /// Write to the framebuffer at byte offset `o` then flush to the display
    /// (Linux fb write + defio). Bytes past the fb end are dropped.
    fn write(&self, o: u64, b: &[u8]) -> KResult<usize> {
        let (fb_va, bytes) = match crate::kva_of(self.idx) { Some(v) => v, None => return Ok(b.len()) };
        if o >= bytes { return Ok(0); }
        let n = ((bytes - o) as usize).min(b.len());
        // SAFETY: fb_va is the HHDM mapping of the scanout for `bytes`; o+n <= bytes; CPL=0 write of the caller's bytes into the device-backed framebuffer.
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), (fb_va + o) as *mut u8, n); }
        crate::flush();
        Ok(n)
    }
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
    let user_ok = |p: u64, len: u64| p != 0 && p < hal::USER_VA_END && p + len < hal::USER_VA_END;
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
            // We don't reallocate the scanout: accept iff the requested mode
            // matches the current geometry/bpp, else EINVAL (Linux rejects an
            // unsupported mode rather than silently ignoring it).
            if !user_ok(arg, 160) { return efault(); }
            let cur = match crate::var_of(idx) { Some(v) => v, None => return Some(-(Errno::Eagain.as_i32() as i64)) };
            // SAFETY: arg validated for 160 B; read the requested FbVarScreeninfo from the caller's AS.
            let req_v = unsafe { core::ptr::read_volatile(arg as *const crate::FbVarScreeninfo) };
            if req_v.xres != cur.xres || req_v.yres != cur.yres || req_v.bits_per_pixel != cur.bits_per_pixel {
                return Some(-(Errno::Einval.as_i32() as i64));
            }
            Some(0)
        }
        crate::FBIOPAN_DISPLAY => {
            // Single-buffer scanout: only (xoffset,yoffset)=(0,0) is valid;
            // a pan to it flushes the current contents. Else EINVAL.
            if !user_ok(arg, 160) { return efault(); }
            // SAFETY: arg validated for 160 B; read xoffset/yoffset (the first two u32 after the res fields) — read the whole struct.
            let v = unsafe { core::ptr::read_volatile(arg as *const crate::FbVarScreeninfo) };
            if v.xoffset != 0 || v.yoffset != 0 { return Some(-(Errno::Einval.as_i32() as i64)); }
            crate::flush();
            Some(0)
        }
        crate::FBIOGETCMAP | crate::FBIOPUTCMAP => {
            // Truecolor visual has no palette (Linux returns EINVAL for
            // get/put cmap on a DIRECTCOLOR/TRUECOLOR fb).
            Some(-(Errno::Einval.as_i32() as i64))
        }
        crate::FBIOGET_VBLANK => {
            // struct fb_vblank: flags u32, count u32, vcount, hcount, ... (32 B).
            // No CRTC vblank counter — report "no vblank info" (flags=0).
            if !user_ok(arg, 32) { return efault(); }
            // SAFETY: arg validated for 32 B; zero the fb_vblank struct in the caller's AS.
            unsafe { core::ptr::write_bytes(arg as *mut u8, 0, 32); }
            Some(0)
        }
        // ---- by-value-arg ioctls (arg is NOT a pointer) ----
        crate::FBIOBLANK => {
            // arg = FB_BLANK_* level (0..4) by value. Validate; no DPMS hw, so
            // accept and no-op (blank state isn't observable on virtio-gpu).
            if crate::is_blank_level(arg as u32) { Some(0) } else { Some(-(Errno::Einval.as_i32() as i64)) }
        }
        crate::FBIO_WAITFORVSYNC => {
            // No real vsync IRQ: flush the scanout (push pending pixels) and
            // return immediately. Userspace uses this as "present my frame".
            crate::flush();
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

/// Boot-time registration. Called from kernel_main once devfs +
/// drm core are up. Currently registers a single /dev/fb0 inode;
/// the crate::register() per-CRTC setup happens once 47's modeset
/// path lands.
/// # SAFETY: caller is the boot path; pre-init.
/// # C: O(1)
pub fn init() {
    devfs::register("/dev/fb0", Arc::new(FbInode { idx: 0 }) as InodeRef);
}
