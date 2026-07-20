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
    // The interruptible form closes signal-before-sleep: a pending unmasked
    // signal changes Sleeping back to Runnable before schedule can switch away.
    unsafe { wait.park_interruptible_with_deadline(0); }
}

/// Schedule after VFS registered current and dropped the rwsem gate. # C: sleeps
pub fn schedule_after_park() {
    // SAFETY: caller is parked on an inode wait list and holds no rwsem gate.
    unsafe { schedule(); }
}

/// Wake all tasks waiting for this inode state transition. # C: O(N_waiters)
pub fn wake(key: usize) {
    let wait = { WAITERS.lock().get(&key).cloned() };
    let Some(wait) = wait else { return };
    wait.wake_all();

    // Do not retain an unbounded map of one-shot inode identities. Holding the
    // map lock prevents a new registrar from selecting a replacement list
    // while this entry is evaluated. A registrar that already holds `wait`
    // keeps its Arc count above map+this local reference until it has either
    // published itself or finished, so removing cannot lose its wakeup.
    let mut waiters = WAITERS.lock();
    let mapped = waiters.get(&key).is_some_and(|mapped| Arc::ptr_eq(mapped, &wait));
    if mapped && !wait.has_waiters() && Arc::strong_count(&wait) == 2 {
        waiters.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_KEY: usize = usize::MAX;

    #[test]
    fn wake_prunes_an_empty_keyed_wait_list() {
        WAITERS.lock().insert(EMPTY_KEY, Arc::new(WaitList::new()));
        wake(EMPTY_KEY);
        assert!(!WAITERS.lock().contains_key(&EMPTY_KEY));
    }
}
