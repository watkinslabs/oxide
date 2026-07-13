extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use sync::{Spinlock, TaskList as WaitClass};

use super::{schedule, WaitList};

static WAITERS: Spinlock<BTreeMap<usize, Arc<WaitList>>, WaitClass> = Spinlock::new(BTreeMap::new());

fn wait_list(key: usize) -> Arc<WaitList> {
    let mut g = WAITERS.lock();
    g.entry(key).or_insert_with(|| Arc::new(WaitList::new())).clone()
}

/// Register current on the quota-off wait list; VFS holds its quota wait lock. # C: O(log N)
pub fn park(key: usize) {
    let wl = wait_list(key);
    // SAFETY: VFS calls from the running task before immediately scheduling through `schedule_after_park`.
    unsafe { wl.park(); }
}

/// Yield after [`park`] has registered current and VFS dropped its lock. # C: sleeps
pub fn schedule_after_park() {
    // SAFETY: caller just parked current on a WaitList and holds no VFS quota wait lock.
    unsafe { schedule(); }
}

/// Wake every task sleeping on the given quota wait list. # C: O(N_waiters)
pub fn wake(key: usize) {
    let wl = { WAITERS.lock().get(&key).cloned() };
    if let Some(wl) = wl { wl.wake_all(); }
}
