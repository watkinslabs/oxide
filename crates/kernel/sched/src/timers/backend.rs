use sync::{Guard, Spinlock, Timer as TimerLock};
pub(super) use crate::timer_queue::{WallEntry, WallQueue};

pub(super) struct State {
    pub wall: WallQueue,
}

impl State {
    const fn new() -> Self { Self { wall: WallQueue::new() } }
}

// Process-wide POSIX timer state lives on the thread-group leader. Sibling
// threads can enter timer syscalls concurrently, so preemption state alone is
// not sufficient serialization.
static STATE: Spinlock<State, TimerLock> = Spinlock::new(State::new());

pub(super) fn lock() -> Guard<'static, State, TimerLock> { STATE.lock() }

pub(super) fn try_lock() -> Option<Guard<'static, State, TimerLock>> { STATE.try_lock() }
