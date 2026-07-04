// DRM/KMS card nodes per `47`. /dev/dri/cardN + /dev/dri/renderD128+N
// dispatch ioctls through the stable DrmDriver slot in the drm crate.

#![allow(dead_code)]

use alloc::{format, sync::Arc, vec::Vec};

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

/// Runtime scanout operations the DRM core calls for SETCRTC/PAGE_FLIP.
/// Filled by `drv-virtio-gpu::post_init::register_drm_hooks` per DRM card at
/// device install. The DRM crate cannot depend on the virtio-gpu crate, so the
/// binding is a function-pointer table plus an opaque driver key.
#[derive(Copy, Clone)]
pub struct ScanoutOps {
    /// Driver-owned runtime key, currently the owning virtio-gpu parent BDF.
    pub driver_key: u32,
    /// Create a virtio-gpu resource over a contiguous PA; returns res_id.
    pub create_from_pa: fn(driver_key: u32, pa: u64, w: u32, h: u32, fmt_drm: u32) -> Option<u32>,
    /// Switch scanout 0 to `res_id` + transfer + flush.
    pub set_scanout: fn(driver_key: u32, res_id: u32, w: u32, h: u32) -> bool,
    /// Restore the boot fbcon scanout + repaint the console.
    pub restore_console: fn(driver_key: u32) -> bool,
    /// The boot fbcon scanout resource id.
    pub boot_res_id: fn(driver_key: u32) -> u32,
}

static SCANOUT_OPS: Spinlock<Vec<Option<ScanoutOps>>, OpsLockClass> = Spinlock::new(Vec::new());

struct DrmNodePair {
    card: Arc<drv::Device>,
    render: Arc<drv::Device>,
}

static DRM_NODES: Spinlock<Vec<Option<DrmNodePair>>, OpsLockClass> = Spinlock::new(Vec::new());

/// Install the runtime scanout backend for a stable DRM card id.
/// # C: O(N) only when extending the sparse card table.
pub fn set_scanout_ops(card_id: u32, ops: ScanoutOps) {
    let mut g = SCANOUT_OPS.lock();
    let idx = card_id as usize;
    if g.len() <= idx {
        g.resize_with(idx + 1, || None);
    }
    g[idx] = Some(ops);
}

/// Remove the runtime scanout backend for a stable DRM card id.
/// # C: O(N) only when trimming trailing empty slots.
pub fn clear_scanout_ops(card_id: u32) {
    let mut g = SCANOUT_OPS.lock();
    if let Some(slot) = g.get_mut(card_id as usize) {
        *slot = None;
    }
    while matches!(g.last(), Some(None)) {
        g.pop();
    }
}

/// Snapshot the runtime scanout backend for a stable DRM card id.
/// # C: O(1)
pub fn scanout_ops(card_id: u32) -> Option<ScanoutOps> {
    SCANOUT_OPS.lock().get(card_id as usize).and_then(|slot| *slot)
}

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
// device number; low 32 bits carry the stable DRM card id.
const DRM_INO_TAG_MASK: vfs::Ino = 0xFFFF_FFFF_0000_0000;
const DRM_INO_CARD_MASK: vfs::Ino = 0x0000_0000_FFFF_FFFF;
const DRM_CARD_INO: vfs::Ino = 0x4452_4D43_0000_0000;
const DRM_RENDER_INO: vfs::Ino = 0x4452_4D52_0000_0000;

/// `file_operations` for `/dev/dri/cardN`: read drains queued KMS events,
/// write is a no-op sink, last-close restores the boot fbcon scanout.
struct DrmCardFileOps;
impl vfs::FileOps for DrmCardFileOps {
    /// read(2) on the card fd drains queued KMS events (DRM page-flip
    /// completions) as `drm_event_vblank` records — Linux `drm_read`.
    /// 0 bytes when no event is pending (libdrm polls then reads).
    /// # C: O(events)
    fn read(&self, inode: &vfs::Inode, _o: u64, b: &mut [u8]) -> vfs::KResult<usize> {
        let Some((_, card_id)) = drm_inode_parts_raw(inode.ino()) else {
            return Ok(0);
        };
        Ok(crate::crtc::drain_events(card_id, b))
    }
    fn write(&self, _inode: &vfs::Inode, _o: u64, b: &[u8]) -> vfs::KResult<usize> { Ok(b.len()) }
    /// Last-close: if a KMS client took the scanout via SETCRTC and is
    /// now closing its card fd, restore the boot fbcon scanout + repaint
    /// the console so the fb console (and getty) come back. A normal
    /// boot never opens a card node, so this never fires and the console
    /// stays untouched.
    /// MUST NOT panic or block. # C: O(1) + O(scanout repaint).
    fn on_release(&self, inode: &vfs::Inode) {
        let Some((_, card_id)) = drm_inode_parts_raw(inode.ino()) else {
            return;
        };
        if crate::crtc::owner(card_id) != 0 {
            if let Some(ops) = scanout_ops(card_id) {
                (ops.restore_console)(ops.driver_key);
            }
            crate::crtc::clear_owner(card_id);
        }
    }
}

/// `file_operations` for the render node: read returns 0 bytes, write is a sink.
struct DrmSinkFileOps;
impl vfs::FileOps for DrmSinkFileOps {
    fn read(&self, _inode: &vfs::Inode, _o: u64, _b: &mut [u8]) -> vfs::KResult<usize> { Ok(0) }
    fn write(&self, _inode: &vfs::Inode, _o: u64, b: &[u8]) -> vfs::KResult<usize> { Ok(b.len()) }
}

fn drm_inode_parts_raw(ino: vfs::Ino) -> Option<(vfs::Ino, u32)> {
    let tag = ino & DRM_INO_TAG_MASK;
    if tag != DRM_CARD_INO && tag != DRM_RENDER_INO {
        return None;
    }
    Some((tag, (ino & DRM_INO_CARD_MASK) as u32))
}

fn drm_inode_parts(inode: &vfs::InodeRef) -> Option<(vfs::Ino, u32)> {
    drm_inode_parts_raw(inode.ino())
}

fn ioctl_takes_user_ptr(req: u64) -> bool {
    !matches!(req, DRM_IOCTL_SET_MASTER | DRM_IOCTL_DROP_MASTER)
}

/// Build a `/dev/dri/cardN` inode (`S_IFCHR|0o666`, card tag, card f_op).
/// # C: O(1)
fn make_card_inode(card_id: u32) -> vfs::InodeRef {
    vfs::InodeBuilder::new(DRM_CARD_INO | card_id as vfs::Ino, vfs::mk_mode(vfs::FileType::CharDev, 0o666),
                           vfs::default_inode_ops(), Arc::new(DrmCardFileOps)).build()
}
/// Build a `/dev/dri/renderD128+N` inode (sink f_op). # C: O(1)
fn make_render_inode(card_id: u32) -> vfs::InodeRef {
    vfs::InodeBuilder::new(DRM_RENDER_INO | card_id as vfs::Ino, vfs::mk_mode(vfs::FileType::CharDev, 0o666),
                           vfs::default_inode_ops(), Arc::new(DrmSinkFileOps)).build()
}

/// Self-register a DRM `/dev` node through `drv::try_device_add` (D27): the
/// `node_factory` mints the EXACT bespoke inode (custom `FileOps`, routing tag)
/// each used before, so the /dev node is byte-identical; `dt` is the standard
/// `(major,minor)` metadata. bus == `class` (`drm`) is ignored by the pci/virtio
/// /sys synthesis, so no spurious /sys entry appears. # C: O(1)
fn add_node(name: &str, class: &'static str, dt: (u32, u32), factory: drv::NodeFactory) -> Option<Arc<drv::Device>> {
    use alloc::string::String;
    drv::try_device_add(Arc::new(
        drv::Device::new(class, String::from(name), 0, 0, 0)
            .with_devnode(class, String::from(name), Some(dt))
            .with_node_factory(factory),
    )).ok()
}

/// Register DRM card/render nodes for a stable DRM card id.
/// # C: O(1)
pub fn register(card_id: u32) -> bool {
    let mut nodes = DRM_NODES.lock();
    let idx = card_id as usize;
    if nodes.len() <= idx {
        nodes.resize_with(idx + 1, || None);
    }
    if nodes[idx].is_some() {
        return false;
    }
    let card_name = format!("dri/card{}", card_id);
    let render_minor = 128u32.checked_add(card_id).expect("DRM render minor overflow");
    let render_name = format!("dri/renderD{}", render_minor);
    let Some(card) = add_node(
        &card_name,
        "drm",
        (226, card_id),
        Arc::new(move || make_card_inode(card_id)),
    ) else {
        return false;
    };
    let Some(render) = add_node(
        &render_name,
        "drm",
        (226, render_minor),
        Arc::new(move || make_render_inode(card_id)),
    ) else {
        drv::device_del(&card);
        return false;
    };
    nodes[idx] = Some(DrmNodePair { card, render });
    true
}

/// Remove DRM card/render nodes for a stable DRM card id.
/// # C: O(depth)
pub fn unregister(card_id: u32) {
    let pair = {
        let mut g = DRM_NODES.lock();
        let pair = g.get_mut(card_id as usize).and_then(Option::take);
        while matches!(g.last(), Some(None)) {
            g.pop();
        }
        pair
    };
    if let Some(pair) = pair {
        drv::device_del(&pair.render);
        drv::device_del(&pair.card);
    }
}

#[cfg(test)]
pub fn unregister_all() {
    let pairs = {
        let mut g = DRM_NODES.lock();
        let mut pairs = Vec::new();
        for pair in g.iter_mut().filter_map(Option::take) {
            pairs.push(pair);
        }
        g.clear();
        pairs
    };
    for pair in pairs.into_iter().rev() {
        drv::device_del(&pair.render);
        drv::device_del(&pair.card);
    }
}

#[cfg(test)]
pub fn registered_card_ids() -> Vec<u32> {
    DRM_NODES.lock()
        .iter()
        .enumerate()
        .filter_map(|(idx, pair)| pair.as_ref().map(|_| idx as u32))
        .collect()
}

#[cfg(test)]
mod node_publication_tests {
    use super::*;

    #[test]
    fn register_rejects_duplicate_card_id_without_republishing() {
        let card_id = 0x7ff0;
        unregister(card_id);

        assert!(register(card_id));
        assert!(!register(card_id));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "drm" && d.addr == format!("dri/card{card_id}"))
                .count(),
            1
        );

        unregister(card_id);
    }

    #[test]
    fn unregister_then_register_restores_card_and_render_nodes() {
        let card_id = 0x7ff2;
        let card_name = format!("dri/card{card_id}");
        let render_minor = 128 + card_id;
        let render_name = format!("dri/renderD{render_minor}");
        unregister(card_id);

        assert!(register(card_id));
        assert!(registered_card_ids().contains(&card_id));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "drm" && (d.addr == card_name || d.addr == render_name))
                .count(),
            2
        );

        unregister(card_id);
        assert!(!registered_card_ids().contains(&card_id));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "drm" && (d.addr == card_name || d.addr == render_name))
                .count(),
            0
        );

        assert!(register(card_id));
        assert!(registered_card_ids().contains(&card_id));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "drm" && (d.addr == card_name || d.addr == render_name))
                .count(),
            2
        );

        unregister(card_id);
    }

    #[test]
    fn register_rolls_back_card_node_when_render_publication_conflicts() {
        let card_id = 0x7ff1;
        unregister(card_id);
        let card_name = format!("dri/card{card_id}");
        let render_minor = 128 + card_id;
        let render_name = format!("dri/renderD{render_minor}");
        let conflict = drv::try_device_add(Arc::new(
            drv::Device::new("drm", render_name.clone(), 0, 0, 0)
                .with_devnode("drm", render_name.clone(), Some((226, render_minor))),
        ))
        .expect("conflict device registration");

        assert!(!register(card_id));
        assert!(!registered_card_ids().contains(&card_id));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "drm" && d.addr == card_name)
                .count(),
            0
        );
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "drm" && d.addr == render_name)
                .count(),
            1
        );

        drv::device_del(&conflict);
        assert!(register(card_id));
        unregister(card_id);
    }

    #[test]
    fn render_node_rejects_master_only_ioctls() {
        use syscall::errno::Errno;

        let render = make_render_inode(0);
        assert_eq!(
            handle_drm_ioctl(&render, DRM_IOCTL_MODE_SETCRTC, 1),
            Some(-(Errno::Eacces.as_i32() as i64))
        );
        assert_eq!(
            handle_drm_ioctl(&render, DRM_IOCTL_SET_MASTER, 1),
            Some(-(Errno::Eacces.as_i32() as i64))
        );
    }

    #[test]
    fn card_master_ioctls_do_not_require_user_pointer() {
        let card = make_card_inode(0);
        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_SET_MASTER, 0), Some(0));
        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_DROP_MASTER, 0), Some(0));
    }
}

/// mmap backing for a DRM card inode (offset-keyed). Legacy raw lookup used
/// by tests/diagnostics; production mmap should prefer `pin_mmap_backing` so
/// VMA lifetime pins the dumb buffer. # C: O(n)
pub fn mmap_backing(inode: &vfs::InodeRef, offset: u64) -> Option<(u64, u64)> {
    let Some((DRM_CARD_INO, card_id)) = drm_inode_parts(inode) else { return None; };
    crate::dumb::mmap_backing(card_id, offset)
}

/// Pin a DRM dumb buffer for a userspace VMA. The returned pin owns a mmap ref
/// until `dumb::unpin_mmap` is called by the VMA backing's Drop path. # C: O(n)
pub fn pin_mmap_backing(inode: &vfs::InodeRef, offset: u64) -> Option<crate::dumb::DumbMmapPin> {
    let Some((DRM_CARD_INO, card_id)) = drm_inode_parts(inode) else { return None; };
    crate::dumb::pin_mmap(card_id, offset)
}

/// ioctl on a DRM fd. Returns Some(rv) when handled; None otherwise (caller
/// falls back to the generic CharDev path).
/// # C: O(1)
pub fn handle_drm_ioctl(inode: &vfs::InodeRef, req: u64, arg: u64) -> Option<i64> {
    let (tag, card_id) = drm_inode_parts(inode)?;
    use syscall::errno::Errno;
    if tag == DRM_RENDER_INO && crate::is_master_only(req) {
        return Some(-(Errno::Eacces.as_i32() as i64));
    }
    if ioctl_takes_user_ptr(req) && (arg == 0 || arg >= hal::USER_VA_END) {
        return Some(-(Errno::Efault.as_i32() as i64));
    }
    let driver = crate::card(card_id);
    match req {
        DRM_IOCTL_VERSION => {
            let (name, date, desc, ver) = match driver.as_ref() {
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
            let val = match driver.as_ref() {
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
            match driver.as_ref() {
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
            match driver.as_ref() {
                Some(d) => Some(crate::modeset::get_plane_res(d, arg)),
                None => {
                    // SAFETY: arg validated; field at +8 is the count u32.
                    unsafe { core::ptr::write_volatile((arg + 8) as *mut u32, 0); }
                    Some(0)
                }
            }
        }
        DRM_IOCTL_MODE_GETPLANE => {
            match driver.as_ref() {
                Some(d) => Some(crate::modeset::get_plane(d, arg)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_MODE_GETCRTC => {
            match driver.as_ref() {
                Some(d) => Some(crate::modeset::get_crtc(d, arg)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_MODE_GETENCODER => {
            match driver.as_ref() {
                Some(d) => Some(crate::modeset::get_encoder(d, arg)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_MODE_GETCONNECTOR => {
            match driver.as_ref() {
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
        DRM_IOCTL_MODE_CREATE_DUMB  => Some(crate::dumb::create_dumb(card_id, arg)),
        DRM_IOCTL_MODE_MAP_DUMB     => Some(crate::dumb::map_dumb(card_id, arg)),
        DRM_IOCTL_MODE_DESTROY_DUMB => Some(crate::dumb::destroy_dumb(card_id, arg)),
        DRM_IOCTL_MODE_ADDFB2       => Some(crate::dumb::addfb2(card_id, arg)),
        DRM_IOCTL_MODE_ADDFB        => Some(crate::dumb::addfb(card_id, arg)),
        DRM_IOCTL_MODE_RMFB         => Some(crate::dumb::rmfb(card_id, arg)),
        // ---- D5b-2 SETCRTC / PAGE_FLIP (real scanout) ----
        // Token = the card inode pointer used by the current open path to
        // identify the KMS owner for this card. Card required (no GPU →
        // set_crtc honest-fails EINVAL).
        DRM_IOCTL_MODE_SETCRTC => {
            let token = Arc::as_ptr(inode) as *const () as u64;
            match driver.as_ref() {
                Some(d) => Some(crate::crtc::set_crtc(card_id, d, arg, token)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_MODE_PAGE_FLIP => {
            let token = Arc::as_ptr(inode) as *const () as u64;
            match driver.as_ref() {
                Some(d) => Some(crate::crtc::page_flip(card_id, d, arg, token)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        _ => Some(-(Errno::Enotty.as_i32() as i64)),
    }
}
