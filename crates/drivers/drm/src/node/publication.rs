use alloc::{format, sync::Arc, vec::Vec};

use sync::{Spinlock, TaskList as OpsLockClass};
use vfs::File;

use crate::uapi::{DRM_MAJOR, DRM_NODE_MODE};

use super::auth::{
    clear_authorized_for_card, clear_master_owner, clear_unique_ready_for_card, file_token,
    release_file_magic, release_master_owner, release_unique_ready,
};
#[cfg(test)]
use super::auth::reset_test_state;
use super::scanout::scanout_ops;

struct DrmNodePair {
    card: Arc<drv::Device>,
    render: Arc<drv::Device>,
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
    /// completions) as `drm_event_vblank` records — Linux `drm_read`
    /// (`drivers/gpu/drm/drm_file.c`).
    ///
    /// Linux NEVER returns 0 here: with nothing queued it answers `-EAGAIN`
    /// for `O_NONBLOCK` and otherwise sleeps on `file_priv->event_wait`. A
    /// 0-byte read is EOF to a GLib fd source, which then tears the source
    /// down and re-dispatches it forever.
    /// # C: O(events)
    fn read_file(&self, file: &File, _o: u64, b: &mut [u8]) -> vfs::KResult<usize> {
        let Some((_, card_id)) = drm_inode_parts_raw(file.inode().ino()) else {
            return Err(vfs::VfsError::Einval);
        };
        let nonblock = file.flags().contains(vfs::OpenFlags::O_NONBLOCK);
        crate::crtc::drain_events_blocking(card_id, file_token(file), b, nonblock)
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
        release_unique_ready(card_id, token);
        crate::crtc::clear_file_events(card_id, token);
        if crate::crtc::is_owner(card_id, token) {
            if let Some(ops) = scanout_ops(card_id) {
                (ops.restore_console)(ops.driver_key);
            }
            crate::crtc::clear_owner(card_id);
        }
    }
}

/// `file_operations` for the render node. Render fds share the DRM ioctl path
/// but `handle_drm_ioctl` rejects KMS/master-only requests for render inodes.
pub(super) struct DrmSinkFileOps;
impl vfs::FileOps for DrmSinkFileOps {
    /// Render minors share `drm_read` with card minors in Linux — one
    /// `drm_file` event path, one fops table. A render fd simply never has
    /// events queued, so a blocking read sleeps and a non-blocking one gets
    /// `-EAGAIN`. It must NOT return 0: that is EOF to a GLib fd source, which
    /// tears the source down and re-dispatches it forever. Same defect the card
    /// node carried (B1484).
    /// # C: O(1) + park
    fn read_file(&self, file: &File, _o: u64, b: &mut [u8]) -> vfs::KResult<usize> {
        let Some((_, card_id)) = drm_inode_parts_raw(file.inode().ino()) else {
            return Err(vfs::VfsError::Einval);
        };
        let nonblock = file.flags().contains(vfs::OpenFlags::O_NONBLOCK);
        crate::crtc::drain_events_blocking(card_id, file_token(file), b, nonblock)
    }
    fn write(&self, _inode: &vfs::Inode, _o: u64, _b: &[u8]) -> vfs::KResult<usize> {
        Err(vfs::VfsError::Einval)
    }
    fn on_release_file(&self, file: &File) {
        let token = file_token(file);
        release_file_magic(token);
        if let Some((_, card_id)) = drm_inode_parts_raw(file.inode().ino()) {
            release_unique_ready(card_id, token);
        }
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

/// Build a `/dev/dri/cardN` inode (`S_IFCHR|DRM_NODE_MODE`, card tag, card f_op).
/// `i_rdev` MUST carry the real `(DRM_MAJOR, N)` dev_t: userspace `stat(2)`s the
/// node and passes `st_rdev` to logind's `TakeDevice(major,minor)`. Without it
/// `st_rdev` is 0, mutter calls `TakeDevice(0,0)`, and logind's
/// `sd_device_new_from_devnum(0:0)` misses → `ENODEV` ("No GPUs found") — the
/// greeter never opens the GPU. Mirrors Linux `init_special_inode` setting
/// `i_rdev` on every char node. # C: O(1)
pub(super) fn make_card_inode(card_id: u32) -> vfs::InodeRef {
    vfs::InodeBuilder::new(DRM_CARD_INO | card_id as vfs::Ino, vfs::mk_mode(vfs::FileType::CharDev, DRM_NODE_MODE),
                           vfs::default_inode_ops(), Arc::new(DrmCardFileOps))
        .poll_subs_arc(card_poll_subs(card_id))
        .rdev(vfs::Devt::new(DRM_MAJOR, card_id).raw()).build()
}

/// Per-card epoll subscriber set, shared between the card inode and the event
/// queue that wakes it. The inode adopts this exact `Arc` (`poll_subs_arc`, the
/// same arrangement `/dev/fuse` uses) so a waiter subscribes to the object
/// `crtc::queue_flip_event` notifies — a second set would leave every poller
/// registered on something nothing ever wakes.
/// # C: O(cards)
pub(crate) fn card_poll_subs(card_id: u32) -> Arc<vfs::PollSubscribers> {
    let mut g = CARD_POLL.lock();
    if let Some((_, s)) = g.iter().find(|(id, _)| *id == card_id) { return s.clone(); }
    let s = Arc::new(vfs::PollSubscribers::new());
    g.push((card_id, s.clone()));
    s
}

static CARD_POLL: Spinlock<Vec<(u32, Arc<vfs::PollSubscribers>)>, OpsLockClass> =
    Spinlock::new(Vec::new());
/// Build a `/dev/dri/renderD128+N` inode (sink f_op). `i_rdev` = `(226, 128+N)`
/// (Linux DRM render minors start at 128), same rationale as the card node. # C: O(1)
pub(super) fn make_render_inode(card_id: u32) -> vfs::InodeRef {
    vfs::InodeBuilder::new(DRM_RENDER_INO | card_id as vfs::Ino, vfs::mk_mode(vfs::FileType::CharDev, DRM_NODE_MODE),
                           vfs::default_inode_ops(), Arc::new(DrmSinkFileOps))
        .rdev(vfs::Devt::new(DRM_MAJOR, crate::uapi::DRM_RENDER_MINOR_BASE + card_id).raw()).build()
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

/// Register DRM primary + render nodes for a stable DRM card id.
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
    let render_minor = crate::uapi::DRM_RENDER_MINOR_BASE + card_id;
    let render_name = format!("dri/renderD{}", render_minor);
    let Some(card) = add_node(
        &card_name,
        "drm",
        (DRM_MAJOR, card_id),
        Arc::new(move || make_card_inode(card_id)),
        parent.clone(),
    ) else {
        return false;
    };
    let Some(render) = add_node(
        &render_name,
        "drm",
        (DRM_MAJOR, render_minor),
        Arc::new(move || make_render_inode(card_id)),
        parent,
    ) else {
        drv::device_del(&card);
        return false;
    };
    nodes[idx] = Some(DrmNodePair { card, render });
    true
}

/// Remove DRM primary + render nodes for a stable DRM card id.
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
        clear_unique_ready_for_card(card_id);
        drv::device_del(&pair.render);
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
        drv::device_del(&pair.render);
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

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::{Dentry, File, OpenFlags};

    fn open_file(inode: vfs::InodeRef) -> Arc<File> {
        let dentry = Dentry::new_anon(Arc::clone(&inode));
        File::new(inode, dentry, OpenFlags::O_RDWR)
    }

    #[test]
    fn page_flip_events_are_open_file_poll_read_state() {
        let _guard = crate::TEST_LOCK.lock();
        const CARD: u32 = 0x7ee0;
        const OTHER_CARD: u32 = 0x7ee1;
        crate::crtc::clear_card_state(CARD);
        crate::crtc::clear_card_state(OTHER_CARD);

        let owner = open_file(make_card_inode(CARD));
        let owner_dup = Arc::clone(&owner);
        let other = open_file(make_card_inode(CARD));
        let other_card = open_file(make_card_inode(OTHER_CARD));
        let mut buf = [0u8; 64];

        assert_eq!(owner.poll(), vfs::POLL_OUT);
        // Linux `drm_read` never returns 0 on an EMPTY queue: `-EAGAIN` for
        // O_NONBLOCK, otherwise it sleeps on `event_wait`. 0 would be EOF.
        assert_eq!(owner.read(&mut buf), Err(vfs::VfsError::Eagain));
        crate::crtc::queue_flip_event(CARD, file_token(&owner), 7, 0xfeed_beef);

        assert_eq!(owner.poll(), vfs::POLL_IN | vfs::POLL_OUT);
        assert_eq!(owner_dup.poll(), vfs::POLL_IN | vfs::POLL_OUT);
        assert_eq!(other.poll(), vfs::POLL_OUT);
        assert_eq!(other_card.poll(), vfs::POLL_OUT);

        let mut tiny = [0u8; 4];
        assert_eq!(owner_dup.read(&mut tiny), Ok(0));
        assert_eq!(owner.poll(), vfs::POLL_IN | vfs::POLL_OUT);

        let rec = core::mem::size_of::<crate::DrmEventVblank>();
        assert_eq!(owner.read(&mut buf), Ok(rec));
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), crate::DRM_EVENT_FLIP_COMPLETE);
        assert_eq!(u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]), 0xfeed_beef);
        assert_eq!(owner.poll(), vfs::POLL_OUT);

        crate::crtc::clear_card_state(CARD);
        crate::crtc::clear_card_state(OTHER_CARD);
    }
}
