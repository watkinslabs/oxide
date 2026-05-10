// DRM/KMS card per `47`. /dev/dri/card0 + /dev/dri/renderD128
// dispatch ioctls through the registered DrmDriver in the drm
// crate. virtio-gpu installs itself as the first card via
// drv_virtio_gpu::install_with_drm; real per-card responses
// flow from there.

#![allow(dead_code)]

use alloc::sync::Arc;

use drm::{
    DRM_IOCTL_VERSION, DRM_IOCTL_GET_CAP, DRM_IOCTL_GET_UNIQUE,
    DRM_IOCTL_SET_VERSION, DRM_IOCTL_MODE_GETRESOURCES,
};

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

// Fallback strings used when no DrmDriver is registered (e.g.
// QEMU launched without -device virtio-gpu-pci).
const FALLBACK_NAME: &str = "oxide";
const FALLBACK_DATE: &str = "20260509";
const FALLBACK_DESC: &str = "Oxide DRM (no GPU)";

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
            // Look up the registered DrmDriver (card 0); fall back
            // to "oxide / no-GPU" strings when none registered.
            let cards = drm::cards();
            let (name, date, desc, ver) = match cards.first() {
                Some(d) => (d.name(), d.date(), d.desc(), d.version()),
                None    => (FALLBACK_NAME, FALLBACK_DATE, FALLBACK_DESC, (1, 6, 0)),
            };
            // SAFETY: arg validated < USER_VA_END; struct drm_version is 88 bytes.
            let mut v: DrmVersion = unsafe { core::ptr::read_volatile(arg as *const DrmVersion) };
            v.version_major     = ver.0 as i32;
            v.version_minor     = ver.1 as i32;
            v.version_patchlevel = ver.2 as i32;
            // SAFETY: each user pointer + len validated < USER_VA_END before write; CPL=0 writes through caller's AS.
            unsafe {
                if v.name != 0 && v.name < hal::USER_VA_END && v.name_len > 0 {
                    let n = (v.name_len as usize).min(name.len());
                    for i in 0..n {
                        core::ptr::write_volatile((v.name + i as u64) as *mut u8, name.as_bytes()[i]);
                    }
                }
                if v.date != 0 && v.date < hal::USER_VA_END && v.date_len > 0 {
                    let n = (v.date_len as usize).min(date.len());
                    for i in 0..n {
                        core::ptr::write_volatile((v.date + i as u64) as *mut u8, date.as_bytes()[i]);
                    }
                }
                if v.desc != 0 && v.desc < hal::USER_VA_END && v.desc_len > 0 {
                    let n = (v.desc_len as usize).min(desc.len());
                    for i in 0..n {
                        core::ptr::write_volatile((v.desc + i as u64) as *mut u8, desc.as_bytes()[i]);
                    }
                }
            }
            v.name_len = name.len() as u64;
            v.date_len = date.len() as u64;
            v.desc_len = desc.len() as u64;
            // SAFETY: arg validated; struct drm_version is 88 bytes; CPL=0 writes through caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut DrmVersion, v); }
            Some(0)
        }
        DRM_IOCTL_GET_CAP => {
            // struct drm_get_cap { capability u64; value u64; }.
            // Delegate to driver.cap(); fall back to drm::default_cap.
            // SAFETY: arg validated < USER_VA_END; aligned u64 read of capability + write of value.
            let cap = unsafe { core::ptr::read_volatile(arg as *const u64) };
            let cards = drm::cards();
            let val = match cards.first() {
                Some(d) => d.cap(cap),
                None    => drm::default_cap(cap),
            };
            // SAFETY: arg validated; cap struct is 16 bytes; value at +8.
            unsafe { core::ptr::write_volatile((arg + 8) as *mut u64, val); }
            Some(0)
        }
        DRM_IOCTL_GET_UNIQUE => Some(0),
        DRM_IOCTL_SET_VERSION => Some(0),
        DRM_IOCTL_MODE_GETRESOURCES => {
            // drm_mode_card_res: 4 ptrs (32 B) + count_fbs/crtcs/
            // connectors/encoders (4×u32) + min/max width/height
            // (4×u32). Total 64 B.
            let cards = drm::cards();
            let (count_fbs, count_crtcs, count_conns, count_encs) = match cards.first() {
                Some(d) => d.resource_counts(),
                None    => (0, 0, 0, 0),
            };
            let (min_w, max_w, min_h, max_h) = match cards.first() {
                Some(d) => d.dim_bounds(),
                None    => (0, 0, 0, 0),
            };
            // SAFETY: arg validated; struct ≥ 64 B; aligned u32 stores.
            unsafe {
                core::ptr::write_volatile((arg + 32) as *mut u32, count_fbs);
                core::ptr::write_volatile((arg + 36) as *mut u32, count_crtcs);
                core::ptr::write_volatile((arg + 40) as *mut u32, count_conns);
                core::ptr::write_volatile((arg + 44) as *mut u32, count_encs);
                core::ptr::write_volatile((arg + 48) as *mut u32, min_w);
                core::ptr::write_volatile((arg + 52) as *mut u32, max_w);
                core::ptr::write_volatile((arg + 56) as *mut u32, min_h);
                core::ptr::write_volatile((arg + 60) as *mut u32, max_h);
            }
            Some(0)
        }
        _ => Some(-(Errno::Enotty.as_i32() as i64)),
    }
}
