// /dev/fb0 — Linux fbdev shim per docs/48. Routes FBIO* ioctls
// through the fbdev crate's per-CRTC registry. fbdev::register
// gets called when 47 (DRM/KMS) binds an FB to a CRTC; until then
// /dev/fb0's ioctls return Eagain.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

const FB0_INO_BASE: Ino = 0x7001_0000;

pub struct FbInode {
    pub idx: u32,
}

impl Inode for FbInode {
    fn ino(&self) -> Ino { FB0_INO_BASE | self.idx as u64 }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}

/// FBIO* ioctl handler. Returns `Some(rv)` if the ioctl is one of
/// FBIOGET_VSCREENINFO / FBIOGET_FSCREENINFO etc; falls back to
/// `None` for unknown commands so the generic CharDev path runs.
/// # C: O(1)
pub fn handle_fbdev_ioctl(inode: &InodeRef, req: u64, arg: u64) -> Option<i64> {
    let tag = inode.ino() & 0xFFFF_FFFF_0000_0000;
    if tag != FB0_INO_BASE & 0xFFFF_FFFF_0000_0000 { return None; }
    let idx = (inode.ino() & 0xFFFF) as u32;
    use syscall::errno::Errno;
    if arg == 0 || arg >= hal::USER_VA_END {
        return Some(-(Errno::Efault.as_i32() as i64));
    }
    match req {
        fbdev::FBIOGET_VSCREENINFO => {
            let v = match fbdev::var_of(idx) {
                Some(v) => v,
                None    => return Some(-(Errno::Eagain.as_i32() as i64)),
            };
            // SAFETY: arg validated < USER_VA_END; FbVarScreeninfo is 160 B; aligned write into caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut fbdev::FbVarScreeninfo, v); }
            Some(0)
        }
        fbdev::FBIOGET_FSCREENINFO => {
            let f = match fbdev::fix_of(idx) {
                Some(f) => f,
                None    => return Some(-(Errno::Eagain.as_i32() as i64)),
            };
            // SAFETY: arg validated; FbFixScreeninfo is 80 B; aligned write into caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut fbdev::FbFixScreeninfo, f); }
            Some(0)
        }
        fbdev::FBIOPUT_VSCREENINFO => Some(0),     // accept, no-op until DRM modeset wires
        fbdev::FBIOPAN_DISPLAY    => Some(0),
        fbdev::FBIOBLANK          => {
            // arg is a small integer (FB_BLANK_*) passed by value, not a pointer.
            let _level = arg as u32;
            Some(0)
        }
        _ => None,
    }
}

/// Boot-time registration. Called from kernel_main once devfs +
/// drm core are up. Currently registers a single /dev/fb0 inode;
/// the fbdev::register() per-CRTC setup happens once 47's modeset
/// path lands.
/// # SAFETY: caller is the boot path; pre-init.
/// # C: O(1)
pub fn init() {
    crate::devfs::register("/dev/fb0", Arc::new(FbInode { idx: 0 }) as InodeRef);
}
