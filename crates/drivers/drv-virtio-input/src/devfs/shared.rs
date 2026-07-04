use alloc::sync::Arc;

use sync::{Spinlock, TaskList as NodesLockClass};
use vfs::{File, Ino, Inode, InodeRef};

use crate::evdev_queue::MAX_EVDEV;

pub(crate) const EVDEV_INO_BASE: Ino = 0x7400_0000;
pub(crate) const EVDEV_FILE_REVOKED: u64 = 1 << 0;

/// Backend-private state (`i_private`) for `/dev/input/event<id>`.
pub struct EvdevData {
    pub id: u32,
}

/// `id -> node inode` registry.
pub(crate) static EVDEV_NODES: Spinlock<[Option<InodeRef>; MAX_EVDEV], NodesLockClass> =
    Spinlock::new([const { None }; MAX_EVDEV]);

/// `id -> drv::Device` for model-owned evdev publication.
pub(crate) static EVDEV_DEVICES: Spinlock<[Option<Arc<drv::Device>>; MAX_EVDEV], NodesLockClass> =
    Spinlock::new([const { None }; MAX_EVDEV]);

/// `EVIOCGRAB` owner per evdev id.
pub(crate) static EVDEV_GRABS: Spinlock<[usize; MAX_EVDEV], NodesLockClass> =
    Spinlock::new([0; MAX_EVDEV]);

pub(crate) fn file_token(file: &File) -> usize {
    file as *const File as usize
}

pub(crate) fn evdev_id(inode: &Inode) -> Option<u32> {
    inode.private::<EvdevData>().map(|d| d.id)
}

pub(crate) fn grabbed_by_other(id: u32, token: usize) -> bool {
    let owner = EVDEV_GRABS.lock()[(id as usize).min(MAX_EVDEV - 1)];
    owner != 0 && owner != token
}

pub(crate) fn release_grab(id: u32, token: usize) {
    let slot = (id as usize).min(MAX_EVDEV - 1);
    let mut grabs = EVDEV_GRABS.lock();
    if grabs[slot] == token {
        grabs[slot] = 0;
        crate::evdev_queue::queue(id).waiters.wake_one();
        crate::devfs::notify_evdev_subs(id);
    }
}
