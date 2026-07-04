use alloc::{format, sync::Arc, vec::Vec};

use sync::{Spinlock, TaskList as OpsLockClass};
use vfs::File;

use super::auth::{
    clear_authorized_for_card, clear_master_owner, file_token, release_file_magic,
    release_master_owner,
};
#[cfg(test)]
use super::auth::reset_test_state;
use super::scanout::scanout_ops;

struct DrmNodePair {
    card: Arc<drv::Device>,
}

static DRM_NODES: Spinlock<Vec<Option<DrmNodePair>>, OpsLockClass> = Spinlock::new(Vec::new());

// High-bits tags keep the DRM char-device inodes distinct from every other
// device number; low 32 bits carry the stable DRM card id.
pub(super) const DRM_INO_TAG_MASK: vfs::Ino = 0xFFFF_FFFF_0000_0000;
pub(super) const DRM_INO_CARD_MASK: vfs::Ino = 0x0000_0000_FFFF_FFFF;
pub(super) const DRM_CARD_INO: vfs::Ino = 0x4452_4D43_0000_0000;
pub(super) const DRM_RENDER_INO: vfs::Ino = 0x4452_4D52_0000_0000;

pub(super) struct DrmCardFileOps;
impl vfs::FileOps for DrmCardFileOps {
    /// read(2) on the card fd drains queued KMS events (DRM page-flip
    /// completions) as `drm_event_vblank` records — Linux `drm_read`.
    /// 0 bytes when no event is pending (libdrm polls then reads).
    /// # C: O(events)
    fn read_file(&self, file: &File, _o: u64, b: &mut [u8]) -> vfs::KResult<usize> {
        let Some((_, card_id)) = drm_inode_parts_raw(file.inode().ino()) else {
            return Ok(0);
        };
        Ok(crate::crtc::drain_events(card_id, file_token(file), b))
    }
    fn poll_open_file(&self, file: &File) -> u32 {
        let Some((_, card_id)) = drm_inode_parts_raw(file.inode().ino()) else {
            return vfs::POLL_ERR;
        };
        let mut mask = vfs::POLL_OUT;
        if crate::crtc::has_events(card_id, file_token(file)) {
            mask |= vfs::POLL_IN;
        }
        mask
    }
    fn write(&self, _inode: &vfs::Inode, _o: u64, _b: &[u8]) -> vfs::KResult<usize> {
        Err(vfs::VfsError::Einval)
    }
    /// Last-close: if a KMS client took the scanout via SETCRTC and is
    /// now closing its card fd, restore the boot fbcon scanout + repaint
    /// the console so the fb console (and getty) come back. A normal
    /// boot never opens a card node, so this never fires and the console
    /// stays untouched.
    /// MUST NOT panic or block. # C: O(1) + O(scanout repaint).
    fn on_release_file(&self, file: &File) {
        let Some((_, card_id)) = drm_inode_parts_raw(file.inode().ino()) else {
            return;
        };
        let token = file_token(file);
        release_master_owner(card_id, token);
        release_file_magic(token);
        crate::crtc::clear_file_events(card_id, token);
        if crate::crtc::is_owner(card_id, token) {
            if let Some(ops) = scanout_ops(card_id) {
                (ops.restore_console)(ops.driver_key);
            }
            crate::crtc::clear_owner(card_id);
        }
    }
}

/// `file_operations` for the render node. Render nodes stay unpublished until
/// a real render/GEM UAPI exists; the private test inode must not fake writes.
pub(super) struct DrmSinkFileOps;
impl vfs::FileOps for DrmSinkFileOps {
    fn read(&self, _inode: &vfs::Inode, _o: u64, _b: &mut [u8]) -> vfs::KResult<usize> { Ok(0) }
    fn write(&self, _inode: &vfs::Inode, _o: u64, _b: &[u8]) -> vfs::KResult<usize> {
        Err(vfs::VfsError::Einval)
    }
    fn on_release_file(&self, file: &File) {
        release_file_magic(file_token(file));
    }
}

pub(super) fn drm_inode_parts_raw(ino: vfs::Ino) -> Option<(vfs::Ino, u32)> {
    let tag = ino & DRM_INO_TAG_MASK;
    if tag != DRM_CARD_INO && tag != DRM_RENDER_INO {
        return None;
    }
    Some((tag, (ino & DRM_INO_CARD_MASK) as u32))
}

pub(super) fn drm_inode_parts(inode: &vfs::InodeRef) -> Option<(vfs::Ino, u32)> {
    drm_inode_parts_raw(inode.ino())
}

/// Build a `/dev/dri/cardN` inode (`S_IFCHR|0o666`, card tag, card f_op).
/// # C: O(1)
pub(super) fn make_card_inode(card_id: u32) -> vfs::InodeRef {
    vfs::InodeBuilder::new(DRM_CARD_INO | card_id as vfs::Ino, vfs::mk_mode(vfs::FileType::CharDev, 0o666),
                           vfs::default_inode_ops(), Arc::new(DrmCardFileOps)).build()
}
/// Build a `/dev/dri/renderD128+N` inode (sink f_op). # C: O(1)
pub(super) fn make_render_inode(card_id: u32) -> vfs::InodeRef {
    vfs::InodeBuilder::new(DRM_RENDER_INO | card_id as vfs::Ino, vfs::mk_mode(vfs::FileType::CharDev, 0o666),
                           vfs::default_inode_ops(), Arc::new(DrmSinkFileOps)).build()
}

/// Self-register a DRM `/dev` node through `drv::try_device_add` (D27): the
/// `node_factory` mints the EXACT bespoke inode (custom `FileOps`, routing tag)
/// each used before, so the /dev node is byte-identical; `dt` is the standard
/// `(major,minor)` metadata. bus == `class` (`drm`) is ignored by the pci/virtio
/// /sys synthesis, so no spurious /sys entry appears. # C: O(1)
fn add_node(
    name: &str,
    class: &'static str,
    dt: (u32, u32),
    factory: drv::NodeFactory,
    parent: Option<(&'static str, alloc::string::String)>,
) -> Option<Arc<drv::Device>> {
    use alloc::string::String;
    let mut dev = drv::Device::new(class, String::from(name), 0, 0, 0)
        .with_devnode(class, String::from(name), Some(dt))
        .with_node_factory(factory);
    if let Some((bus, addr)) = parent {
        dev = dev.with_parent(bus, addr);
    }
    drv::try_device_add(Arc::new(dev)).ok()
}

/// Register a DRM card node for a stable DRM card id.
/// # C: O(1)
pub fn register(card_id: u32, parent: Option<(&'static str, alloc::string::String)>) -> bool {
    let mut nodes = DRM_NODES.lock();
    let idx = card_id as usize;
    if nodes.len() <= idx {
        nodes.resize_with(idx + 1, || None);
    }
    if nodes[idx].is_some() {
        return false;
    }
    let card_name = format!("dri/card{}", card_id);
    let Some(card) = add_node(
        &card_name,
        "drm",
        (226, card_id),
        Arc::new(move || make_card_inode(card_id)),
        parent,
    ) else {
        return false;
    };
    nodes[idx] = Some(DrmNodePair { card });
    true
}

/// Remove the DRM card node for a stable DRM card id.
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
        clear_master_owner(card_id);
        clear_authorized_for_card(card_id);
        drv::device_del(&pair.card);
    }
}

#[cfg(test)]
/// Remove all registered DRM nodes and reset test-only node state.
/// # C: O(N_nodes * depth)
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
        drv::device_del(&pair.card);
    }
    reset_test_state();
}

#[cfg(test)]
/// Return stable DRM card ids with published nodes.
/// # C: O(N_nodes)
pub fn registered_card_ids() -> Vec<u32> {
    DRM_NODES.lock()
        .iter()
        .enumerate()
        .filter_map(|(idx, pair)| pair.as_ref().map(|_| idx as u32))
        .collect()
}
