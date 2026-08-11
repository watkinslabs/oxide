extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use sync::{Spinlock, TaskList as WaitClass};

use super::{schedule, WaitList};

struct Waiters {
    readers: Arc<WaitList>,
    writers: Arc<WaitList>,
}

static WAITERS: Spinlock<BTreeMap<usize, Arc<Waiters>>, WaitClass> = Spinlock::new(BTreeMap::new());

fn waiters_for(key: usize) -> Arc<Waiters> {
    let mut waiters = WAITERS.lock();
    waiters.entry(key).or_insert_with(|| Arc::new(Waiters {
        readers: Arc::new(WaitList::new()), writers: Arc::new(WaitList::new()),
    })).clone()
}

/// Register current while VFS holds the rwsem registration gate. # C: O(log N)
pub fn park(key: usize) {
    park_reader(key);
}

/// Register a rwsem reader while its registration gate is held. # C: O(log N)
pub fn park_reader(key: usize) {
    let wait = waiters_for(key);
    // SAFETY: VFS immediately drops its registration gate and calls schedule_after_park.
    // The interruptible form closes signal-before-sleep: a pending unmasked
    // signal changes Sleeping back to Runnable before schedule can switch away.
    unsafe { wait.readers.prepare_to_wait_interruptible(); }
}

/// Register a rwsem writer while its registration gate is held. # C: O(log N)
pub fn park_writer(key: usize) {
    let wait = waiters_for(key);
    // SAFETY: rwsem immediately drops its registration gate and schedules.
    unsafe { wait.writers.prepare_to_wait_interruptible(); }
}

/// Register a rwsem waiter in its reader or writer FIFO. # C: O(log N)
pub fn park_rwsem(key: usize, writer: bool) {
    if writer { park_writer(key); } else { park_reader(key); }
}

/// Schedule after VFS registered current and dropped the rwsem gate. # C: sleeps
pub fn schedule_after_park() {
    // SAFETY: caller is parked on an inode wait list and holds no rwsem gate.
    unsafe { schedule(); }
}

/// Wake all tasks waiting for this inode state transition. # C: O(N_waiters)
pub fn wake(key: usize) {
    let waiters = { WAITERS.lock().get(&key).cloned() };
    let Some(waiters) = waiters else { return };
    waiters.readers.wake_all();
    waiters.writers.wake_all();
    prune(key, &waiters);
}

/// Wake a rwsem's next writer, or its blocked reader batch when no writer
/// remains. The rwsem holds its registration gate across this choice.
/// # C: O(N_readers) in a reader phase, O(1) in a writer phase
pub fn wake_rwsem(key: usize, writers_waiting: bool) {
    let waiters = { WAITERS.lock().get(&key).cloned() };
    let Some(waiters) = waiters else { return };
    if writers_waiting { waiters.writers.wake_one(); } else { waiters.readers.wake_all(); }
    prune(key, &waiters);
}

fn prune(key: usize, wait: &Arc<Waiters>) {

    // Do not retain an unbounded map of one-shot inode identities. Holding the
    // map lock prevents a new registrar from selecting a replacement list
    // while this entry is evaluated. A registrar that already holds `wait`
    // keeps its Arc count above map+this local reference until it has either
    // published itself or finished, so removing cannot lose its wakeup.
    let mut waiters = WAITERS.lock();
    let mapped = waiters.get(&key).is_some_and(|mapped| Arc::ptr_eq(mapped, wait));
    if mapped && !wait.readers.has_waiters() && !wait.writers.has_waiters()
        && Arc::strong_count(wait) == 2
    {
        waiters.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_KEY: usize = usize::MAX;

    #[test]
    fn wake_prunes_an_empty_keyed_wait_list() {
        WAITERS.lock().insert(EMPTY_KEY, Arc::new(Waiters {
            readers: Arc::new(WaitList::new()), writers: Arc::new(WaitList::new()),
        }));
        wake(EMPTY_KEY);
        assert!(!WAITERS.lock().contains_key(&EMPTY_KEY));
    }
}
