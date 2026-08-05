extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap};
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Modules as ModulesLockClass, Spinlock};

pub(crate) const WAIT_MUTEX: u8 = 1;
pub(crate) const WAIT_SEM: u8 = 2;
pub(crate) const WAIT_COMPLETION: u8 = 3;
pub(crate) const WAIT_QUEUE: u8 = 4;

static CELLS: Spinlock<BTreeMap<(usize, u8), Box<WaitCell>>, ModulesLockClass> =
    Spinlock::new(BTreeMap::new());

pub(crate) struct WaitCell {
    pub(crate) gate: Spinlock<(), ModulesLockClass>,
    waiters: AtomicU32,
    #[cfg(target_os = "oxide-kernel")]
    wait: sched::live::WaitList,
}

impl WaitCell {
    fn new() -> Self {
        Self {
            gate: Spinlock::new(()),
            waiters: AtomicU32::new(0),
            #[cfg(target_os = "oxide-kernel")]
            wait: sched::live::WaitList::new(),
        }
    }

    pub(crate) fn park_locked(&self) {
        self.waiters.fetch_add(1, Ordering::AcqRel);
        #[cfg(target_os = "oxide-kernel")]
        // Callers (mutex/sem/completion/waitqueue KPI) run in process context with the scheduler
        // live, and self.wait lives in a WaitCell that CELLS heap-owns and never frees.
        // SAFETY: WaitList::park needs the running task on a live runqueue, which the above gives;
        // the waiters bump precedes it so a racing wake_one still sees this waiter.
        unsafe {
            self.wait.park();
        }
    }

    pub(crate) fn yield_parked(&self) {
        #[cfg(target_os = "oxide-kernel")]
        // SAFETY: park_yield requires the caller to be already Sleeping on a wait list — the KPI
        // wrappers only reach here after park_locked enqueued current on self.wait, and they drop
        // the resource gate in between so the waker that must call wake_one cannot deadlock
        // against us; each wrapper re-checks its condition in a loop after this returns.
        unsafe {
            sched::live::park_yield();
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        core::hint::spin_loop();
        self.waiters.fetch_sub(1, Ordering::AcqRel);
    }

    pub(crate) fn finish_waiter(&self) {
        let _ = self.waiters.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1));
    }

    pub(crate) fn wake_one(&self) {
        if self.waiters.load(Ordering::Acquire) == 0 { return; }
        #[cfg(target_os = "oxide-kernel")]
        self.wait.wake_one();
    }

    pub(crate) fn wake_all(&self) {
        if self.waiters.load(Ordering::Acquire) == 0 { return; }
        #[cfg(target_os = "oxide-kernel")]
        self.wait.wake_all();
    }

    pub(crate) fn active(&self) -> bool {
        self.waiters.load(Ordering::Acquire) != 0
    }
}

pub(crate) fn wait_cell(key: usize, kind: u8) -> &'static WaitCell {
    let mut cells = CELLS.lock();
    let entry = cells.entry((key, kind)).or_insert_with(|| Box::new(WaitCell::new()));
    let ptr: *const WaitCell = &**entry;
    // SAFETY: cells are heap-owned by the global table and are never removed, so the returned reference is stable.
    unsafe { &*ptr }
}
