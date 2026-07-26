// Blocking-read wait abstraction for the TTY core (T4).
//
// Linux blocks a tty reader on `tty->read_wait` with the classic
// `add_wait_queue` / `prepare_to_wait` → re-check condition → `schedule`
// loop (`drivers/tty/n_tty.c:n_tty_read`). The load-bearing property is
// that enqueuing the waiter happens BEFORE the final condition re-check,
// and that both the enqueue and the producer's (queue-bytes + wake) run
// under the SAME serializing lock — so a byte arriving in the window
// between the reader's first empty-check and its sleep cannot be lost.
//
// `TtyWait` abstracts the three primitives so the read loop is identical
// in the kernel (real scheduler park/wake) and in hosted tests (a model
// that can inject a byte exactly at the race point). No `dyn` — the tty
// core is generic over `W: TtyWait`, mirroring the HAL-trait rule (07§5).
//
// The lost-wakeup-free ordering lives in `TtyStruct::read` (core.rs):
//
//   loop {
//     fast path: if input ready → return                  (no lock held)
//     LOCK port
//       wait.park_prepare()       // enqueue self as waiter
//       if ldisc.has_input() { wait.park_abort(); UNLOCK; continue; }  // recheck
//     UNLOCK port
//     wait.park_commit()          // schedule()
//   }
//
//   receive_from_driver (producer):
//     LOCK port
//       ldisc.receive_buf(...)    // queue bytes
//     UNLOCK port
//     wait.wake_all()             // wake parked readers
//
// Because `park_prepare` (under the lock) precedes the re-check (also
// under the lock), and the producer queues bytes under the same lock
// before waking, any byte queued after our re-check is necessarily
// accompanied by a `wake_all` that finds us already enqueued. A byte
// queued before our re-check is seen by the re-check itself. Neither
// interleaving sleeps forever.

/// Wait primitive driving a tty reader's block/wake. Three calls,
/// matching Linux `prepare_to_wait` / `finish_wait` / `wake_up`.
pub trait TtyWait {
    /// IRQ gate for the port lock (`06§3.1`).
    ///
    /// The port lock is shared with a HARD-IRQ producer: the UART RX ISR calls
    /// `receive_from_driver`, and the timer tick drains fbcon answerback into
    /// the same path. A reader holding it plainly in process context would be
    /// spun on by that ISR forever (`skizm.md` 3.0e / 3.0f). It therefore has
    /// to be `lock_irqsave`, and the gate rides here rather than as a third
    /// type parameter on `TtyStruct` — `TtyWait` already carries exactly the
    /// kernel-vs-host distinction the gate needs, so every existing alias and
    /// test keeps its shape.
    type Irq: sync::IrqGate;

    /// Enqueue the current reader as a waiter and mark intent-to-sleep.
    /// Called UNDER the port lock, BEFORE the condition re-check. Must
    /// be idempotent across the prepare→abort→prepare retry loop.
    /// # C: O(1)
    fn park_prepare(&self);

    /// Undo a `park_prepare` when the post-enqueue re-check found input
    /// (the reader will loop and drain instead of sleeping). Called
    /// under the port lock.
    /// # C: O(1)
    fn park_abort(&self);

    /// Actually sleep: yield the CPU until a `wake_all` runs. Called
    /// with NO lock held. Returns when the reader should re-check.
    /// # C: O(1) + sleep
    fn park_commit(&self);

    /// Wake every parked reader. Called by the producer (RX path) AFTER
    /// queueing bytes under the port lock, with the port lock released.
    /// # C: O(N) parked readers
    fn wake_all(&self);

    /// Sleep until a `wake_all`, OR until the monotonic clock reaches
    /// `deadline_ns` (a VTIME timer). Called with NO lock held, after
    /// the same prepare→recheck dance as `park_commit`. The default
    /// forwards to `park_commit` (no clock at this layer for hosts that
    /// do not implement a timer) — the kernel impl stamps a wake
    /// deadline so the periodic deadline scanner rouses the task.
    /// # C: O(1) + sleep
    fn park_commit_deadline(&self, _deadline_ns: u64) {
        self.park_commit();
    }

    /// True when the current reader has an unblocked pending signal and a
    /// blocking read must abort with EINTR (Linux `signal_pending` in
    /// `n_tty_read`'s wait loop). Checked AFTER each wake, BEFORE
    /// re-draining. The kernel impl reads `current.sigpending & !sigmask`;
    /// the host default is `false` (hosted tests have no scheduler /
    /// signal state — the signal-interrupt path is kernel-only).
    /// # C: O(1)
    fn should_interrupt(&self) -> bool {
        false
    }

    /// Monotonic nanoseconds (VTIME deadline base). The kernel impl reads
    /// `hal::TimerOps::monotonic_ns`; the host default returns 0 (hosted
    /// VMIN/VTIME tests drive the decision fn directly with synthetic
    /// elapsed values rather than a real clock).
    /// # C: O(1)
    fn now_ns(&self) -> u64 {
        0
    }
}

/// Host-test `TtyWait`: a real blocking wait built on a `Mutex`+`Condvar`
/// so a SECOND thread can deliver a byte through `receive_from_driver`
/// while a reader is parked — a genuine concurrent test of the port-lock
/// serialization, not a single-threaded simulation. `park_commit` blocks
/// until `wake_all` is called OR a wake was already pending (the wake that
/// raced ahead of the sleep is not lost — that is the whole point).
///
/// The `seq` counter records the global ordering of every primitive call
/// so the headline test can assert the prepare-then-recheck ordering held.
#[cfg(any(test, feature = "hosted"))]
pub mod host {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Condvar, Mutex};

    use super::TtyWait;

    #[derive(Default)]
    struct WaitInner {
        /// A wake is pending (set by wake_all, consumed by park_commit).
        /// Survives a wake that races ahead of the sleep — the bug class
        /// this whole task fixes.
        wake_pending: bool,
        /// A reader is currently enqueued (park_prepare without a matching
        /// abort/commit).
        parked: bool,
    }

    /// Observable event counters (Arc-shared so the test reads them after).
    #[derive(Default)]
    pub struct Counters {
        pub prepares: AtomicU32,
        pub aborts: AtomicU32,
        pub commits: AtomicU32,
        pub wakes: AtomicU32,
    }

    /// Cloneable handle to a single shared wait queue.
    #[derive(Clone)]
    pub struct HostWait {
        inner: Arc<(Mutex<WaitInner>, Condvar)>,
        pub counters: Arc<Counters>,
    }

    impl Default for HostWait {
        fn default() -> Self {
            Self::new()
        }
    }

    impl HostWait {
        /// Fresh host wait queue.
        /// # C: O(1)
        pub fn new() -> Self {
            Self {
                inner: Arc::new((Mutex::new(WaitInner::default()), Condvar::new())),
                counters: Arc::new(Counters::default()),
            }
        }
    }

    impl TtyWait for HostWait {
        type Irq = sync::NoopIrq;
        fn park_prepare(&self) {
            self.counters.prepares.fetch_add(1, Ordering::SeqCst);
            self.inner.0.lock().unwrap().parked = true;
        }

        fn park_abort(&self) {
            self.counters.aborts.fetch_add(1, Ordering::SeqCst);
            self.inner.0.lock().unwrap().parked = false;
        }

        fn park_commit(&self) {
            self.counters.commits.fetch_add(1, Ordering::SeqCst);
            let (m, cv) = &*self.inner;
            let mut g = m.lock().unwrap();
            // Consume a wake that arrived before we slept (lost-wakeup-
            // free): if one is pending, return immediately. Otherwise
            // block on the condvar until wake_all signals.
            while !g.wake_pending {
                g = cv.wait(g).unwrap();
            }
            g.wake_pending = false;
            g.parked = false;
        }

        fn wake_all(&self) {
            self.counters.wakes.fetch_add(1, Ordering::SeqCst);
            let (m, cv) = &*self.inner;
            let mut g = m.lock().unwrap();
            g.wake_pending = true;
            cv.notify_all();
        }
    }
}

/// Kernel `TtyWait`: parks the running task on a per-tty `WaitList`
/// (`sched::live::WaitList`, the same primitive SysV sem/msg/futex use)
/// and wakes via `WaitList::wake_all`. The port-lock serialization that
/// makes the ordering lost-wakeup-free is owned by `TtyStruct::read` /
/// `receive_from_driver` — this impl supplies only the park/wake
/// mechanism.
#[cfg(target_os = "oxide-kernel")]
pub mod kernel {
    use super::TtyWait;
    use sched::live::WaitList;

    /// Arch IRQ gate for the port lock. `tty` already depends on both hal
    /// crates, so this is a cfg-selected alias rather than a new dependency.
    #[cfg(target_arch = "x86_64")]
    pub type KernelIrq = hal_x86_64::X86IrqGate;
    #[cfg(target_arch = "aarch64")]
    pub type KernelIrq = hal_aarch64::ArmIrqGate;

    /// Per-tty kernel wait queue wrapper.
    pub struct KernelWait {
        wl: WaitList,
    }

    impl Default for KernelWait {
        fn default() -> Self {
            Self::new()
        }
    }

    impl KernelWait {
        /// # C: O(1)
        pub const fn new() -> Self {
            Self { wl: WaitList::new() }
        }
    }

    impl TtyWait for KernelWait {
        type Irq = KernelIrq;
        fn park_prepare(&self) {
            // WaitList::park bumps the current task's Arc strong-count
            // (balanced by wake_all's from_raw), marks it Sleeping, and
            // enqueues it; the matching park_commit issues schedule().
            // SAFETY: invoked by TtyStruct::read on the running task of this CPU under the tty port lock; preempt accounted by the schedule path.
            unsafe { self.wl.park() }
        }

        fn park_abort(&self) {
            // The reader found input after enqueuing and will not sleep;
            // wake the just-parked self so it returns Runnable and is not
            // left dangling on the wait list. wake_all is the cheap
            // correct undo (it only re-enqueues genuinely-Sleeping tasks).
            self.wl.wake_all();
        }

        fn park_commit(&self) {
            // current is Sleeping (set by park) so schedule() will not
            // re-enqueue us — only a wake_all from receive_from_driver rouses us.
            // SAFETY: process context, runqueue installed, preempt-off at the syscall boundary; current task is Sleeping per park.
            unsafe { sched::live::schedule() }
        }

        fn wake_all(&self) {
            self.wl.wake_all()
        }

        fn park_commit_deadline(&self, deadline_ns: u64) {
            // Stamp a wake deadline so the periodic deadline scanner
            // (tick_wake_expired) rouses this reader when the VTIME window
            // expires without an RX wake — the same timed-park primitive
            // poll/pselect6's SO_*TIMEO use. deadline_ns==0 disables the
            // timer (degenerate to a bare park).
            // SAFETY: invoked by TtyStruct::read on the running task of this CPU with no lock held; current task was marked Sleeping by park_prepare; schedule yields and the deadline scanner or an RX wake_all rouses it.
            unsafe {
                self.wl.park_with_deadline(deadline_ns);
                sched::live::schedule();
            }
        }

        fn should_interrupt(&self) -> bool {
            use core::sync::atomic::Ordering;
            match sched::live::current() {
                Some(cur) => {
                    let pending = cur.sigpending.load(Ordering::Acquire);
                    let mask = cur.sigmask.load(Ordering::Acquire);
                    pending & !mask != 0
                }
                None => false,
            }
        }

        fn now_ns(&self) -> u64 {
            #[cfg(target_arch = "x86_64")]
            {
                use hal::TimerOps;
                hal_x86_64::X86TimerOps::monotonic_ns().0
            }
            #[cfg(target_arch = "aarch64")]
            {
                use hal::TimerOps;
                hal_aarch64::ArmTimerOps::monotonic_ns().0
            }
        }
    }
}
