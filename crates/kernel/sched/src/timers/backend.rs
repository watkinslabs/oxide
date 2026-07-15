use sync::{Guard, Spinlock, Timer as TimerLock};

// Process-wide POSIX timer state lives on the thread-group leader. Sibling
// threads can enter timer syscalls concurrently, so preemption state alone is
// not sufficient serialization.
static STATE: Spinlock<(), TimerLock> = Spinlock::new(());

pub(super) fn lock() -> Guard<'static, (), TimerLock> { STATE.lock() }

pub(super) fn try_lock() -> Option<Guard<'static, (), TimerLock>> { STATE.try_lock() }
