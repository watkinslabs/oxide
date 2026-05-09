// DRM/KMS card stub per `35` — first cut for v2 phase 32. Exposes
// `/dev/dri/card0` as a CharDev whose ioctls answer the most common
// userspace probes (DRM_IOCTL_VERSION + DRM_IOCTL_GET_CAP). Real
// modesetting + framebuffer alloc + virtio-gpu ring service ride
// follow-ups; this gets X / Wayland / libdrm probes past the
// open()/ioctl() barrier.
//
// Layout reference: include/uapi/drm/drm.h.

#![cfg(target_os = "oxide-kernel")]
#![allow(dead_code)]

use alloc::sync::Arc;

const DRM_IOCTL_VERSION:    u64 = 0xc040_6400;
const DRM_IOCTL_GET_CAP:    u64 = 0xc010_640c;
const DRM_IOCTL_GET_UNIQUE: u64 = 0xc010_6401;
const DRM_IOCTL_SET_VERSION:u64 = 0xc010_6407;
const DRM_IOCTL_MODE_GETRESOURCES: u64 = 0xc04064a0;

/// `struct drm_version` Linux UAPI (88 bytes on 64-bit).
#[repr(C)]
struct DrmVersion {
    version_major:    i32,
    version_minor:    i32,
    version_patchlevel: i32,
    name_len:    u64,
    name:        u64,   // user pointer
    date_len:    u64,
    date:        u64,   // user pointer
    desc_len:    u64,
    desc:        u64,   // user pointer
}

const DRIVER_NAME: &str = "oxide";
const DRIVER_DATE: &str = "20260507";
const DRIVER_DESC: &str = "Oxide DRM stub";

pub struct DrmCardInode;

impl vfs::Inode for DrmCardInode {
    fn ino(&self) -> vfs::Ino {
        // High-bits tag distinct from other char devices.
        0x4452_4D43_0000_0000u64 | 0
    }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> vfs::KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, b: &[u8]) -> vfs::KResult<usize> { Ok(b.len()) }
}

pub struct DrmRenderInode;

impl vfs::Inode for DrmRenderInode {
    fn ino(&self) -> vfs::Ino {
        0x4452_4D52_0000_0000u64 | 0
    }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> vfs::KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, b: &[u8]) -> vfs::KResult<usize> { Ok(b.len()) }
}

/// /dev/input/event0 — evdev surface. v1 returns 0-byte reads
/// (no events queued) so userspace blocks/poll-empty rather than
/// failing.
pub struct EvdevInode;

impl vfs::Inode for EvdevInode {
    fn ino(&self) -> vfs::Ino {
        0x4556_4456_0000_0000u64 | 0
    }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> vfs::KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, b: &[u8]) -> vfs::KResult<usize> { Ok(b.len()) }
}

/// Register DRM card / render / evdev / input-devices nodes.
/// # C: O(1)
pub fn register() {
    crate::devfs::register("/dev/dri/card0",     Arc::new(DrmCardInode)   as vfs::InodeRef);
    crate::devfs::register("/dev/dri/renderD128", Arc::new(DrmRenderInode) as vfs::InodeRef);
    crate::devfs::register("/dev/input/event0",  Arc::new(EvdevInode)     as vfs::InodeRef);
    crate::devfs::register("/proc/bus/input/devices",
        crate::procfs::StaticFileInode::new(b"\
I: Bus=0019 Vendor=0000 Product=0000 Version=0000\n\
N: Name=\"Oxide synthetic evdev\"\n\
P: Phys=oxide/input0\n\
S: Sysfs=/devices/oxide/input0\n\
H: Handlers=event0\n\
B: EV=3\n\
B: KEY=ffffffffffffffff\n\
") as vfs::InodeRef);
}

/// ioctl on a DRM/evdev fd. Returns Some(rv) when handled; None
/// otherwise (caller falls back to the generic CharDev path).
/// # C: O(1)
pub fn handle_drm_ioctl(inode: &vfs::InodeRef, req: u64, arg: u64) -> Option<i64> {
    let tag = inode.ino() & 0xFFFF_FFFF_0000_0000;
    if tag != 0x4452_4D43_0000_0000 && tag != 0x4452_4D52_0000_0000 {
        return None;
    }
    use syscall::errno::Errno;
    if arg == 0 || arg >= hal::USER_VA_END {
        return Some(-(Errno::Efault.as_i32() as i64));
    }
    match req {
        DRM_IOCTL_VERSION => {
            // SAFETY: arg validated < USER_VA_END; struct drm_version is 88 bytes.
            let mut v: DrmVersion = unsafe { core::ptr::read_volatile(arg as *const DrmVersion) };
            v.version_major = 1;
            v.version_minor = 6;
            v.version_patchlevel = 0;
            // Write back the user-pointer-targeted strings (truncate
            // to the buffer length the caller supplied; userspace
            // libdrm uses two-pass: first call asks for sizes, second
            // call provides buffers).
            // SAFETY: each user pointer + len validated < USER_VA_END before write; CPL=0 writes through caller's AS.
            unsafe {
                if v.name != 0 && v.name < hal::USER_VA_END && v.name_len > 0 {
                    let n = (v.name_len as usize).min(DRIVER_NAME.len());
                    for i in 0..n {
                        core::ptr::write_volatile((v.name + i as u64) as *mut u8, DRIVER_NAME.as_bytes()[i]);
                    }
                }
                if v.date != 0 && v.date < hal::USER_VA_END && v.date_len > 0 {
                    let n = (v.date_len as usize).min(DRIVER_DATE.len());
                    for i in 0..n {
                        core::ptr::write_volatile((v.date + i as u64) as *mut u8, DRIVER_DATE.as_bytes()[i]);
                    }
                }
                if v.desc != 0 && v.desc < hal::USER_VA_END && v.desc_len > 0 {
                    let n = (v.desc_len as usize).min(DRIVER_DESC.len());
                    for i in 0..n {
                        core::ptr::write_volatile((v.desc + i as u64) as *mut u8, DRIVER_DESC.as_bytes()[i]);
                    }
                }
            }
            v.name_len = DRIVER_NAME.len() as u64;
            v.date_len = DRIVER_DATE.len() as u64;
            v.desc_len = DRIVER_DESC.len() as u64;
            // SAFETY: arg validated < USER_VA_END at the top of this fn; struct drm_version is 88 bytes; CPL=0 writes through caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut DrmVersion, v); }
            Some(0)
        }
        DRM_IOCTL_GET_CAP => {
            // Linux drm_get_cap takes (capability u64, value u64).
            // Return value=0 for every cap so libdrm sees a "no
            // capabilities" device, which is correct for our stub.
            // SAFETY: arg validated < USER_VA_END; cap struct is 16 bytes; aligned u64 write.
            unsafe { core::ptr::write_volatile((arg + 8) as *mut u64, 0); }
            Some(0)
        }
        DRM_IOCTL_GET_UNIQUE => Some(0),
        DRM_IOCTL_SET_VERSION => Some(0),
        DRM_IOCTL_MODE_GETRESOURCES => {
            // struct drm_mode_card_res { fb_id_ptr, crtc_id_ptr,
            // connector_id_ptr, encoder_id_ptr (4×u64), then
            // count_fbs, count_crtcs, count_connectors,
            // count_encoders, min_w, max_w, min_h, max_h (8×u32) }.
            // V1: zero counts + max bounds (no display surface).
            // SAFETY: arg validated < USER_VA_END; struct ≥ 64 bytes; aligned u32 stores.
            unsafe {
                for i in 0..8u64 {
                    core::ptr::write_volatile((arg + 32 + i*4) as *mut u32, 0);
                }
            }
            Some(0)
        }
        _ => Some(-(Errno::Enotty.as_i32() as i64)),
    }
}
