extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use sync::{Spinlock, TaskList as WaitClass};

use super::{schedule, WaitList};

static WAITERS: Spinlock<BTreeMap<usize, Arc<WaitList>>, WaitClass> = Spinlock::new(BTreeMap::new());

fn wait_list(key: usize) -> Arc<WaitList> {
    let mut waiters = WAITERS.lock();
    waiters.entry(key).or_insert_with(|| Arc::new(WaitList::new())).clone()
}

/// Register current while VFS holds the rwsem registration gate. # C: O(log N)
pub fn park(key: usize) {
    let wait = wait_list(key);
    // SAFETY: VFS immediately drops its registration gate and calls schedule_after_park.
    unsafe { wait.park(); }
}

/// Schedule after VFS registered current and dropped the rwsem gate. # C: sleeps
pub fn schedule_after_park() {
    // SAFETY: caller is parked on an inode wait list and holds no rwsem gate.
    unsafe { schedule(); }
}

/// Wake all tasks waiting for this inode state transition. # C: O(N_waiters)
pub fn wake(key: usize) {
    let wait = { WAITERS.lock().get(&key).cloned() };
    if let Some(wait) = wait { wait.wake_all(); }
}
