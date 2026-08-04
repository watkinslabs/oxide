// Which pipes are notification pipes.
//
// Linux hangs the queue on `pipe->watch_queue`. The oxide pipe inode's private
// slot already holds its ring, so the queue lives in a side table keyed by the
// same inode identity the FIFO ring table uses: one entry per notification
// pipe, created when the pipe is, removed when its last end closes.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use sync::{LockClass, Spinlock};
use vfs::Inode;

use super::queue::WatchQueue;

/// Lock class for the side table. Taken standalone — every access clones an
/// `Arc<WatchQueue>` out and releases the lock before touching the queue.
struct WatchReg;
impl LockClass for WatchReg { fn rank() -> u16 { 36 } fn name() -> &'static str { "WatchReg" } }

static QUEUES: Spinlock<BTreeMap<usize, Arc<WatchQueue>>, WatchReg> = Spinlock::new(BTreeMap::new());

/// Inode identity, as the FIFO table computes it. # C: O(1)
fn key(inode: &Inode) -> usize { inode as *const Inode as usize }

/// Make this pipe a notification pipe, installing the wake the delivery path
/// uses to bring a blocked reader back. # C: O(log N)
pub fn attach(inode: &vfs::InodeRef) -> Arc<WatchQueue> {
    let q = Arc::new(WatchQueue::new());
    let target = inode.clone();
    q.set_waker(alloc::boxed::Box::new(move || crate::pipe::wake_pipe_readers(&target)));
    QUEUES.lock().insert(key(inode), q.clone());
    q
}

/// The queue behind a notification pipe, or `None` for an ordinary pipe.
/// # C: O(log N)
pub fn queue_of(inode: &Inode) -> Option<Arc<WatchQueue>> {
    QUEUES.lock().get(&key(inode)).cloned()
}

/// Is this inode a notification pipe? # C: O(log N)
pub fn is_notification_pipe(inode: &Inode) -> bool { QUEUES.lock().contains_key(&key(inode)) }

/// Clear the queue's watches, then drop it when the pipe is gone. # C: O(watches log N)
pub fn detach(inode: &Inode) {
    if let Some(queue) = QUEUES.lock().remove(&key(inode)) {
        crate::keyring::detach_watch_queue(&queue);
    }
}
