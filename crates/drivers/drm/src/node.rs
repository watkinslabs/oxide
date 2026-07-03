// DRM/KMS card per `47`. /dev/dri/card0 + /dev/dri/renderD128
// dispatch ioctls through the registered DrmDriver in the drm
// crate. virtio-gpu installs itself as the first card via
// drv_virtio_gpu::install_with_drm; real per-card responses
// flow from there.

#![allow(dead_code)]

use alloc::sync::Arc;

use crate::{
    DRM_IOCTL_VERSION, DRM_IOCTL_GET_CAP, DRM_IOCTL_GET_UNIQUE,
    DRM_IOCTL_SET_VERSION, DRM_IOCTL_MODE_GETRESOURCES,
    DRM_IOCTL_MODE_ATOMIC, DRM_MODE_ATOMIC_TEST_ONLY,
    DRM_IOCTL_SET_CLIENT_CAP, DRM_IOCTL_SET_MASTER, DRM_IOCTL_DROP_MASTER,
    DRM_IOCTL_AUTH_MAGIC, DRM_IOCTL_GET_MAGIC,
    DRM_IOCTL_MODE_GETPLANERESOURCES, DRM_IOCTL_MODE_GETPLANE,
    DRM_IOCTL_MODE_GETCRTC, DRM_IOCTL_MODE_GETENCODER,
    DRM_IOCTL_MODE_GETCONNECTOR,
    DRM_IOCTL_MODE_CREATE_DUMB, DRM_IOCTL_MODE_MAP_DUMB,
    DRM_IOCTL_MODE_DESTROY_DUMB, DRM_IOCTL_MODE_ADDFB2,
    DRM_IOCTL_MODE_ADDFB, DRM_IOCTL_MODE_RMFB,
    DRM_IOCTL_MODE_SETCRTC, DRM_IOCTL_MODE_PAGE_FLIP,
};

use sync::{Spinlock, TaskList as OpsLockClass};

// ============================================================
// Runtime scanout backend hook (filled by drv-virtio-gpu at install)
// ============================================================

/// The runtime scanout operations the DRM core calls for SETCRTC /
/// PAGE_FLIP. Filled by `drv-virtio-gpu::post_init::register_drm_hooks`
/// at device install. The DRM crate cannot depend on the virtio-gpu
/// crate (that crate depends on us), so the binding is a function-pointer
/// table installed at runtime. `None` until a GPU is installed → SETCRTC
/// honest-fails -EINVAL.
#[derive(Copy, Clone)]
pub struct ScanoutOps {
    /// Create a virtio-gpu resource over a contiguous PA; returns res_id.
    pub create_from_pa: fn(pa: u64, w: u32, h: u32, fmt_drm: u32) -> Option<u32>,
    /// Switch scanout 0 to `res_id` + transfer + flush.
    pub set_scanout: fn(res_id: u32, w: u32, h: u32) -> bool,
    /// Restore the boot fbcon scanout + repaint the console.
    pub restore_console: fn() -> bool,
    /// The boot fbcon scanout resource id.
    pub boot_res_id: fn() -> u32,
}

static SCANOUT_OPS: Spinlock<Option<ScanoutOps>, OpsLockClass> = Spinlock::new(None);
static DRM_NODES: Spinlock<[Option<Arc<drv::Device>>; 2], OpsLockClass>
    = Spinlock::new([const { None }; 2]);

/// Install the runtime scanout backend (called once at GPU install).
/// # C: O(1)
pub fn set_scanout_ops(ops: ScanoutOps) { *SCANOUT_OPS.lock() = Some(ops); }

/// Remove the runtime scanout backend during GPU teardown.
/// # C: O(1)
pub fn clear_scanout_ops() { *SCANOUT_OPS.lock() = None; }

/// Snapshot the runtime scanout backend, or `None` if no GPU installed.
/// # C: O(1)
pub fn scanout_ops() -> Option<ScanoutOps> { *SCANOUT_OPS.lock() }

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

// High-bits tags keep the DRM char-device inodes distinct from every other
// device number; the ioctl + mmap dispatchers (`handle_drm_ioctl`,
// `mmap_backing`) route on `inode.ino()` masked to the top 32 bits.
const DRM_CARD_INO:   vfs::Ino = 0x4452_4D43_0000_0000;
const DRM_RENDER_INO: vfs::Ino = 0x4452_4D52_0000_0000;

/// `file_operations` for `/dev/dri/card0`: read drains queued KMS events,
/// write is a no-op sink, last-close restores the boot fbcon scanout.
struct DrmCardFileOps;
impl vfs::FileOps for DrmCardFileOps {
    /// read(2) on the card fd drains queued KMS events (DRM page-flip
    /// completions) as `drm_event_vblank` records — Linux `drm_read`.
    /// 0 bytes when no event is pending (libdrm polls then reads).
    /// # C: O(events)
    fn read(&self, _inode: &vfs::Inode, _o: u64, b: &mut [u8]) -> vfs::KResult<usize> {
        Ok(crate::crtc::drain_events(b))
    }
    fn write(&self, _inode: &vfs::Inode, _o: u64, b: &[u8]) -> vfs::KResult<usize> { Ok(b.len()) }
    /// Last-close: if a KMS client took the scanout via SETCRTC and is
    /// now closing its card fd, restore the boot fbcon scanout + repaint
    /// the console so the fb console (and getty) come back. A normal
    /// boot never opens card0 → this never fires → console untouched.
    /// MUST NOT panic or block. # C: O(1) + O(scanout repaint).
    fn on_release(&self, _inode: &vfs::Inode) {
        if crate::crtc::owner() != 0 {
            if let Some(ops) = scanout_ops() { (ops.restore_console)(); }
            crate::crtc::clear_owner();
        }
    }
}

/// `file_operations` for the render node: read returns 0 bytes, write is a sink.
struct DrmSinkFileOps;
impl vfs::FileOps for DrmSinkFileOps {
    fn read(&self, _inode: &vfs::Inode, _o: u64, _b: &mut [u8]) -> vfs::KResult<usize> { Ok(0) }
    fn write(&self, _inode: &vfs::Inode, _o: u64, b: &[u8]) -> vfs::KResult<usize> { Ok(b.len()) }
}

/// Build the `/dev/dri/card0` inode (`S_IFCHR|0o666`, card tag, card f_op).
/// # C: O(1)
fn make_card_inode() -> vfs::InodeRef {
    vfs::InodeBuilder::new(DRM_CARD_INO, vfs::mk_mode(vfs::FileType::CharDev, 0o666),
                           vfs::default_inode_ops(), Arc::new(DrmCardFileOps)).build()
}
/// Build the `/dev/dri/renderD128` inode (sink f_op). # C: O(1)
fn make_render_inode() -> vfs::InodeRef {
    vfs::InodeBuilder::new(DRM_RENDER_INO, vfs::mk_mode(vfs::FileType::CharDev, 0o666),
                           vfs::default_inode_ops(), Arc::new(DrmSinkFileOps)).build()
}

/// Self-register a DRM `/dev` node through `drv::device_add` (D27): the
/// `node_factory` mints the EXACT bespoke inode (custom `FileOps`, routing tag)
/// each used before, so the /dev node is byte-identical; `dt` is the standard
/// `(major,minor)` metadata. bus == `class` (`drm`) is ignored by the pci/virtio
/// /sys synthesis, so no spurious /sys entry appears. # C: O(1)
fn add_node(name: &str, class: &'static str, dt: (u32, u32), factory: drv::NodeFactory) -> Arc<drv::Device> {
    use alloc::string::String;
    drv::device_add(Arc::new(
        drv::Device::new(class, String::from(name), 0, 0, 0)
            .with_devnode(class, String::from(name), Some(dt))
            .with_node_factory(factory)))
}

/// Register DRM card/render nodes for the first live DRM card.
/// # C: O(1)
pub fn register() {
    let mut nodes = DRM_NODES.lock();
    if nodes[0].is_some() || nodes[1].is_some() {
        return;
    }
    // The nodes are device-model-owned: /dev/dri/card0 (226:0) and
    // renderD128 (226:128) are minted by drv::device_add and removed by
    // drv::device_del when the final DRM card unregisters.
    nodes[0] = Some(add_node("dri/card0",      "drm", (226, 0),   Arc::new(|| make_card_inode())));
    nodes[1] = Some(add_node("dri/renderD128", "drm", (226, 128), Arc::new(|| make_render_inode())));
}

/// Remove DRM card/render nodes after the final live DRM card is gone.
/// # C: O(depth)
pub fn unregister() {
    let nodes = {
        let mut g = DRM_NODES.lock();
        [g[0].take(), g[1].take()]
    };
    for node in nodes.iter().rev().flatten() {
        drv::device_del(node);
    }
}

/// mmap backing for a DRM card inode (offset-keyed). The `offset` is
/// the cookie returned by MODE_MAP_DUMB; it selects which dumb buffer's
/// contiguous PA range to map straight into the process (VmaBacking::
/// PhysRange — same path as /dev/fb0). Returns `None` when `inode` is
/// not the DRM card, or the cookie/handle is unknown — caller then
/// falls through to fbdev / file-backing. # C: O(n)
pub fn mmap_backing(inode: &vfs::InodeRef, offset: u64) -> Option<(u64, u64)> {
    if (inode.ino() & 0xFFFF_FFFF_0000_0000) != 0x4452_4D43_0000_0000 { return None; }
    crate::dumb::mmap_backing(offset)
}

/// ioctl on a DRM fd. Returns Some(rv) when handled; None otherwise (caller
/// falls back to the generic CharDev path).
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
            let cards = crate::cards();
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
            // Delegate to driver.cap(); fall back to crate::default_cap.
            // SAFETY: arg validated < USER_VA_END; aligned u64 read of capability + write of value.
            let cap = unsafe { core::ptr::read_volatile(arg as *const u64) };
            let cards = crate::cards();
            let val = match cards.first() {
                Some(d) => d.cap(cap),
                None    => crate::default_cap(cap),
            };
            // SAFETY: arg validated; cap struct is 16 bytes; value at +8.
            unsafe { core::ptr::write_volatile((arg + 8) as *mut u64, val); }
            Some(0)
        }
        DRM_IOCTL_GET_UNIQUE => Some(0),
        DRM_IOCTL_SET_VERSION => Some(0),
        DRM_IOCTL_MODE_GETRESOURCES => {
            // Real 2-pass enumeration when a card is registered;
            // empty counts (no objects) when none. drm_mode_card_res
            // is 64 B; validated < USER_VA_END above.
            let cards = crate::cards();
            match cards.first() {
                Some(d) => Some(crate::modeset::get_resources(d, arg)),
                None => {
                    // SAFETY: arg validated; struct ≥ 64 B; zero counts + dims.
                    unsafe {
                        for off in [32u64, 36, 40, 44, 48, 52, 56, 60] {
                            core::ptr::write_volatile((arg + off) as *mut u32, 0);
                        }
                    }
                    Some(0)
                }
            }
        }
        DRM_IOCTL_MODE_GETPLANERESOURCES => {
            let cards = crate::cards();
            match cards.first() {
                Some(d) => Some(crate::modeset::get_plane_res(d, arg)),
                None => {
                    // SAFETY: arg validated; field at +8 is the count u32.
                    unsafe { core::ptr::write_volatile((arg + 8) as *mut u32, 0); }
                    Some(0)
                }
            }
        }
        DRM_IOCTL_MODE_GETPLANE => {
            let cards = crate::cards();
            match cards.first() {
                Some(d) => Some(crate::modeset::get_plane(d, arg)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_MODE_GETCRTC => {
            let cards = crate::cards();
            match cards.first() {
                Some(d) => Some(crate::modeset::get_crtc(d, arg)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_MODE_GETENCODER => {
            let cards = crate::cards();
            match cards.first() {
                Some(d) => Some(crate::modeset::get_encoder(d, arg)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_MODE_GETCONNECTOR => {
            let cards = crate::cards();
            match cards.first() {
                Some(d) => Some(crate::modeset::get_connector(d, arg)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_SET_CLIENT_CAP => {
            // struct drm_set_client_cap { capability u64; value u64; }
            // Accept any cap; we don't track per-fd state yet. Mesa /
            // Wayland clients set DRM_CLIENT_CAP_{STEREO_3D,
            // UNIVERSAL_PLANES,ATOMIC,ASPECT_RATIO,WRITEBACK_CONNECTORS}
            // here. Returning 0 means "honored"; real enforcement
            // hangs off per-fd state in a follow-up.
            Some(0)
        }
        DRM_IOCTL_SET_MASTER | DRM_IOCTL_DROP_MASTER => {
            // Master arbitration is moot when there's exactly one
            // KMS client (the compositor). Return 0 so logind /
            // weston-launch are happy.
            Some(0)
        }
        DRM_IOCTL_AUTH_MAGIC | DRM_IOCTL_GET_MAGIC => {
            // Render-node authentication scheme. v1 ships a single
            // unified card node — Auth is implicit. Return 0; magic
            // value 0 is harmless because we never check it.
            Some(0)
        }
        DRM_IOCTL_MODE_ATOMIC => {
            // struct drm_mode_atomic: 56 B. Field 0 = flags u32,
            // field 1 = count_objs u32. v1 admits two cases:
            //   - TEST_ONLY with count_objs == 0 → return 0 (no-op
            //     test always passes)
            //   - any commit with count_objs == 0 and a registered
            //     driver → return 0 (driver opted into ATOMIC by
            //     advertising DRM_CLIENT_CAP_ATOMIC)
            // Anything else returns -EINVAL until property tables
            // land. Userspace probes via TEST_ONLY first, so it
            // sees real-success without us pretending to commit
            // property writes we can't honor.
            // SAFETY: arg validated < USER_VA_END; struct ≥ 56 B; aligned u32 reads of first 8 bytes.
            let flags = unsafe { core::ptr::read_volatile(arg as *const u32) };
            // SAFETY: arg+4 covered by the same 56-byte struct bound; aligned u32 read.
            let count_objs = unsafe { core::ptr::read_volatile((arg + 4) as *const u32) };
            if count_objs == 0
                && (flags & DRM_MODE_ATOMIC_TEST_ONLY) != 0
            {
                return Some(0);
            }
            Some(-(Errno::Einval.as_i32() as i64))
        }
        // ---- D5b-1 dumb buffers + ADDFB2 (offscreen; no scanout) ----
        DRM_IOCTL_MODE_CREATE_DUMB  => Some(crate::dumb::create_dumb(arg)),
        DRM_IOCTL_MODE_MAP_DUMB     => Some(crate::dumb::map_dumb(arg)),
        DRM_IOCTL_MODE_DESTROY_DUMB => Some(crate::dumb::destroy_dumb(arg)),
        DRM_IOCTL_MODE_ADDFB2       => Some(crate::dumb::addfb2(arg)),
        DRM_IOCTL_MODE_ADDFB        => Some(crate::dumb::addfb(arg)),
        DRM_IOCTL_MODE_RMFB         => Some(crate::dumb::rmfb(arg)),
        // ---- D5b-2 SETCRTC / PAGE_FLIP (real scanout) ----
        // Token = the card inode pointer (stable per card; v1 single
        // client). Card required (no GPU → set_crtc honest-fails EINVAL).
        DRM_IOCTL_MODE_SETCRTC => {
            let token = Arc::as_ptr(inode) as *const () as u64;
            match crate::cards().first() {
                Some(d) => Some(crate::crtc::set_crtc(d, arg, token)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_MODE_PAGE_FLIP => {
            let token = Arc::as_ptr(inode) as *const () as u64;
            match crate::cards().first() {
                Some(d) => Some(crate::crtc::page_flip(d, arg, token)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        _ => Some(-(Errno::Enotty.as_i32() as i64)),
    }
}
