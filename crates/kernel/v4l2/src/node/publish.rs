//! Publishing `/dev/videoN` and waking everything watching it.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use sync::{Spinlock, TaskList};
use syscall::errno::Errno;
use vfs::InodeRef;

use crate::device::VideoDevice;
use crate::ids;

/// Per-device node state. Created before the node exists, because the node
/// factory runs inside publication and needs somewhere to record its inode.
struct Node {
    index: u32,
    /// Readers parked in a blocking dequeue.
    waiters: Arc<sched::live::WaitList>,
    /// The node's inode, weakly held so this registry never keeps it alive.
    inode: Weak<vfs::Inode>,
    /// The driver-model object that minted the node, once publication
    /// succeeded.
    model: Option<Arc<drv::Device>>,
}

static NODES: Spinlock<Vec<Node>, TaskList> = Spinlock::new(Vec::new());

/// The wait list blocking dequeues on `index` park on, creating it if the node
/// has not been published yet. One list per device for the life of the boot,
/// so a waker and a waiter can never end up on different lists.
/// # C: O(devices)
pub fn waiters_for(index: u32) -> Arc<sched::live::WaitList> {
    let mut guard = NODES.lock();
    if let Some(node) = guard.iter().find(|n| n.index == index) { return node.waiters.clone(); }
    let waiters = Arc::new(sched::live::WaitList::new());
    guard.push(Node { index, waiters: waiters.clone(), inode: Weak::new(), model: None });
    waiters
}

/// The wait list for `device`. # C: O(devices)
pub fn waiters(device: &Arc<VideoDevice>) -> Arc<sched::live::WaitList> {
    waiters_for(device.index)
}

/// Wake blocked dequeues and every poller of `device`. # C: O(devices)
pub fn wake(device: &Arc<VideoDevice>) {
    let (waiters, inode) = {
        let guard = NODES.lock();
        match guard.iter().find(|n| n.index == device.index) {
            Some(node) => (node.waiters.clone(), node.inode.upgrade()),
            None => return,
        }
    };
    waiters.wake_all();
    if let Some(inode) = inode {
        if let Some(subs) = inode.poll_subscribers() {
            subs.notify_mask(vfs::POLL_IN | vfs::POLL_PRI);
        }
    }
}

/// Remember the inode a node factory just minted, so a completion can wake its
/// pollers. # C: O(devices)
pub fn attach_inode(index: u32, inode: &InodeRef) {
    let mut guard = NODES.lock();
    if let Some(node) = guard.iter_mut().find(|n| n.index == index) {
        node.inode = Arc::downgrade(inode);
    }
}

/// Publish `/dev/videoN` for an already-registered device.
///
/// The node is minted through the driver model, which is what also projects
/// `/sys/class/video4linux/videoN` and sends the uevent a device manager acts
/// on. There is no second path that creates a video node.
/// # C: O(devices)
pub fn publish(device: &Arc<VideoDevice>) -> Result<(), Errno> {
    let index = device.index;
    // The wait list must exist before the factory can run.
    let _ = waiters_for(index);
    let name = alloc::format!("video{}", index);
    let factory: drv::NodeFactory = Arc::new(move || super::fileops::make_inode(index));
    let model = Arc::new(
        drv::Device::new(ids::CLASS_NAME, name.clone(), 0, 0, index)
            .with_devnode(ids::CLASS_NAME, name, Some((ids::VIDEO_MAJOR, device.minor)))
            .with_node_factory(factory),
    );
    match drv::try_device_add(model) {
        Ok(added) => {
            let mut guard = NODES.lock();
            if let Some(node) = guard.iter_mut().find(|n| n.index == index) {
                node.model = Some(added);
            }
            Ok(())
        }
        Err(_) => Err(Errno::Ebusy),
    }
}

/// Withdraw a published node. The wait list stays: a reader parked on it must
/// still be woken, and reusing the index later must not hand out a second list
/// while the first still has sleepers.
/// # C: O(devices)
pub fn withdraw(index: u32) {
    let (model, waiters) = {
        let mut guard = NODES.lock();
        match guard.iter_mut().find(|n| n.index == index) {
            Some(node) => (node.model.take(), node.waiters.clone()),
            None => return,
        }
    };
    if let Some(model) = model { drv::device_del(&model); }
    waiters.wake_all();
}
