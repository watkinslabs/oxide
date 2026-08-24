//! The background state one mount's two threads share.
//!
//! Both threads read knobs a user can turn while they are running, so the
//! knobs live here behind their own locks rather than inside the volume: an
//! attribute write must not have to take the volume lock, which every read of
//! the filesystem holds for as long as it takes to read a block.
//!
//! The wake lists are the other half. A thread parks with a deadline and a
//! condition; a knob write, a checkpoint, or a blocked caller sets the
//! condition and wakes it, so an urgent request does not wait out a sleep
//! that was chosen when nothing was urgent.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sync::{Spinlock, TaskList};

use crate::opts::{BackgroundGc, DiscardUnit};
use syscall::errno::Errno;

use super::ckpt::CkptControl;
use super::ckpt::IoPrio;
use super::discard::DiscardControl;
use super::gc::{GcKthread, GcMode, IdleKind, DEF_IDLE_INTERVAL_SECS};
use super::waits::Waits;

/// Everything the cleaner and the discard thread share with the mount.
pub struct Bg {
    pub gc: Spinlock<GcKthread, TaskList>,
    pub dcc: Spinlock<DiscardControl, TaskList>,
    /// The checkpoint requests waiting to be merged into one write.
    pub cprc: Spinlock<CkptControl, TaskList>,
    /// Flush barriers waiting for the merge thread. The mask is the union of
    /// every caller enrolled in the current window.
    pub flc: Spinlock<FlushControl, TaskList>,
    /// What the mount was asked for. The threads honour it every round, so a
    /// remount that turns cleaning off stops it without stopping the thread.
    pub bggc: Spinlock<BackgroundGc, TaskList>,
    /// Linux's background-GC I/O-awareness policy: all, reads, or none.
    pub bggc_io_aware: AtomicU64,
    /// Set once, by the unmount, and read by both threads every round.
    pub stopping: AtomicBool,
    /// Whether each thread is running, so a caller knows whether parking a
    /// run will ever be looked at.
    pub gc_running: AtomicBool,
    pub discard_running: AtomicBool,
    pub ckpt_running: AtomicBool,
    pub flush_running: AtomicBool,
    /// When the mount last did work for somebody, in the clock's seconds.
    /// Both threads yield to a volume that is being used.
    pub last_op: AtomicU64,
    /// The three Linux idle thresholds. The request threshold is a floor for
    /// both background consumers because every request restarts their clocks.
    idle_interval: AtomicU64,
    discard_idle_interval: AtomicU64,
    gc_idle_interval: AtomicU64,
    /// Cleaning passes blocked callers have been released from.
    fggc_gen: AtomicU64,
    /// Operations that have been through the balance path since the mount.
    balances: AtomicU64,
    pub waits: Waits,
}

#[derive(Debug)]
pub struct FlushControl {
    pub pending: u64,
    pub generation: u64,
    pub inflight: bool,
    pub last: Result<(), Errno>,
}

impl FlushControl {
    pub fn new() -> Self { Self { pending: 0, generation: 0, inflight: false, last: Ok(()) } }
}

impl Bg {
    /// The state a mount starts with. # C: O(MAX_PLIST_NUM)
    pub fn new(bggc: BackgroundGc, unit: DiscardUnit, segs_per_sec: u32) -> Self {
        Self {
            gc: Spinlock::new(GcKthread::new()),
            dcc: Spinlock::new(DiscardControl::new(unit, segs_per_sec)),
            cprc: Spinlock::new(CkptControl::new()),
            flc: Spinlock::new(FlushControl::new()),
            bggc: Spinlock::new(bggc),
            bggc_io_aware: AtomicU64::new(super::gc::BggcIoAware::All as u64),
            stopping: AtomicBool::new(false),
            gc_running: AtomicBool::new(false),
            discard_running: AtomicBool::new(false),
            ckpt_running: AtomicBool::new(false),
            flush_running: AtomicBool::new(false),
            last_op: AtomicU64::new(0),
            idle_interval: AtomicU64::new(DEF_IDLE_INTERVAL_SECS),
            discard_idle_interval: AtomicU64::new(DEF_IDLE_INTERVAL_SECS),
            gc_idle_interval: AtomicU64::new(DEF_IDLE_INTERVAL_SECS),
            fggc_gen: AtomicU64::new(0),
            balances: AtomicU64::new(0),
            waits: Waits::new(),
        }
    }

    /// Whether the threads have been told to wind up. # C: O(1)
    pub fn stopping(&self) -> bool { self.stopping.load(Ordering::Acquire) }

    /// Let the threads run again after a stop.
    ///
    /// The stop flag is how an unmount winds the threads up, and a remount to
    /// read-only uses the same flag for the same reason. Coming back
    /// read-write therefore has to lower it BEFORE starting: a thread spawned
    /// with the flag still up reads it on its first round and exits, leaving a
    /// writable mount with no cleaner and nothing saying so.
    /// # C: O(1)
    pub fn resume(&self) { self.stopping.store(false, Ordering::Release); }

    /// Tell the threads to wind up, whether or not any are running.
    ///
    /// The flag is the MOUNT's statement that no pass may run, which is a
    /// different thing from a thread having noticed it. Raising it here rather
    /// than inside the spawn machinery is what makes a read-only remount's
    /// decision observable on a build that spawns nothing.
    /// # C: O(1)
    pub fn halt(&self) { self.stopping.store(true, Ordering::Release); }

    /// The cleaning mode in force. # C: O(1)
    pub fn gc_mode(&self) -> GcMode { self.gc.lock().mode }

    /// Read the background-GC I/O-awareness policy. # C: O(1)
    pub fn bggc_io_aware(&self) -> super::gc::BggcIoAware {
        super::gc::BggcIoAware::from_u32(self.bggc_io_aware.load(Ordering::Acquire) as u32)
            .unwrap_or(super::gc::BggcIoAware::All)
    }

    /// Set the background-GC I/O-awareness policy. # C: O(1)
    pub fn set_bggc_io_aware(&self, value: u64) {
        self.bggc_io_aware.store(value, Ordering::Release);
    }

    /// Ask for a cleaning pass now, cutting short whatever sleep is running.
    ///
    /// The flag is set before the wake and read after it, so a thread that
    /// was between its condition test and its park still sees the request.
    /// # C: O(1)
    pub fn wake_gc(&self) {
        self.gc.lock().gc_wake = true;
        self.waits.wake_gc();
    }

    /// Ask for a discard round now. # C: O(1)
    pub fn wake_discard(&self) {
        self.dcc.lock().wake = true;
        self.waits.wake_discard();
    }

    /// Enrol this caller for the next merged checkpoint, answering the batch
    /// counter it must wait to pass.
    ///
    /// The enrolment and the wake are one step so a thread between its
    /// condition test and its park still sees the request.
    /// # C: O(1)
    pub fn enrol_checkpoint(&self) -> u64 {
        let seen = self.cprc.lock().enrol();
        self.waits.wake_ckpt();
        seen
    }

    /// Whether the merge thread has moved past `seen`. # C: O(1)
    pub fn checkpoint_served(&self, seen: u64) -> bool {
        self.cprc.lock().generation() != seen
    }

    /// The result of the batch that has just been served. # C: O(1)
    pub fn checkpoint_result(&self) -> Result<(), vfs::VfsError> {
        self.cprc.lock().last()
    }

    pub fn enrol_flush(&self, mask: u64) -> u64 {
        let mut f = self.flc.lock();
        let seen = f.generation.wrapping_add(u64::from(f.inflight));
        f.pending |= mask;
        self.waits.wake_flush();
        seen
    }

    pub fn flush_served(&self, seen: u64) -> bool { self.flc.lock().generation != seen }

    pub fn flush_result(&self) -> Result<(), Errno> { self.flc.lock().last }

    pub fn take_flush(&self) -> Option<u64> {
        let mut f = self.flc.lock();
        if f.pending == 0 { None } else {
            f.inflight = true;
            Some(core::mem::replace(&mut f.pending, 0))
        }
    }

    pub fn finish_flush(&self, result: Result<(), Errno>) {
        let mut f = self.flc.lock();
        f.last = result;
        f.inflight = false;
        f.generation = f.generation.wrapping_add(1);
        self.waits.wake_flush();
    }

    /// The checkpoint merge thread's scheduling control.
    /// # C: O(1)
    pub fn checkpoint_ioprio(&self) -> IoPrio { self.cprc.lock().ioprio }

    /// Change the scheduling control used by the next merge-thread pass.
    /// # C: O(1)
    pub fn set_checkpoint_ioprio(&self, ioprio: IoPrio) {
        self.cprc.lock().ioprio = ioprio;
        self.waits.wake_ckpt();
    }

    /// Put the cleaner into an urgent mode and start it immediately.
    ///
    /// A mode that only took effect at the next ordinary wake would take up
    /// to five minutes to be believed, which is not what urgent means.
    /// # C: O(1)
    pub fn set_gc_mode(&self, mode: GcMode) {
        {
            let mut gc = self.gc.lock();
            gc.mode = mode;
            if mode.is_urgent() { gc.gc_wake = true; }
        }
        if mode.is_urgent() {
            self.waits.wake_gc();
            if mode == GcMode::UrgentHigh { self.wake_discard(); }
        }
    }

    /// Whether a blocked caller is waiting on a cleaning pass. # C: O(1)
    pub fn foreground_waiting(&self) -> bool { self.waits.foreground_waiting() }

    /// How many cleaning passes blocked callers have been released from.
    ///
    /// A counter rather than a flag: a caller enrols by reading it and waits
    /// for it to move, so a pass that finishes between the read and the park
    /// cannot leave the caller waiting for a wake that has already happened.
    /// # C: O(1)
    pub fn foreground_gen(&self) -> u64 { self.fggc_gen.load(Ordering::Acquire) }

    /// Release every caller blocked on the pass that just finished.
    /// # C: O(waiters)
    pub fn finish_foreground(&self) {
        self.fggc_gen.fetch_add(1, Ordering::AcqRel);
        self.waits.wake_foreground();
    }

    /// Note that the mount just did work for somebody. # C: O(1)
    pub fn note_activity(&self, now: u64) {
        self.last_op.store(now, Ordering::Release);
        self.balances.fetch_add(1, Ordering::AcqRel);
    }

    /// Operations that have been through the balance path since the mount.
    ///
    /// The one observable that says the hook at the end of each operation is
    /// in place. A clock cannot serve: a mount whose clock reads zero stamps
    /// zero, which is indistinguishable from never having been touched.
    /// # C: O(1)
    pub fn balance_count(&self) -> u64 { self.balances.load(Ordering::Acquire) }

    /// When the mount last did work for somebody. # C: O(1)
    pub fn last_activity(&self) -> u64 { self.last_op.load(Ordering::Acquire) }

    /// The threshold for one Linux activity clock. # C: O(1)
    pub fn idle_interval(&self, kind: IdleKind) -> u64 {
        match kind {
            IdleKind::Gc => self.gc_idle_interval.load(Ordering::Acquire),
            IdleKind::Discard => self.discard_idle_interval.load(Ordering::Acquire),
            IdleKind::Request => self.idle_interval.load(Ordering::Acquire),
        }
    }

    /// Read one idle threshold. # C: O(1)
    pub fn idle_control(&self, k: super::knobs::Knob) -> u64 {
        match k {
            super::knobs::Knob::IdleInterval => self.idle_interval.load(Ordering::Acquire),
            super::knobs::Knob::DiscardIdleInterval =>
                self.discard_idle_interval.load(Ordering::Acquire),
            super::knobs::Knob::GcIdleInterval =>
                self.gc_idle_interval.load(Ordering::Acquire),
            _ => 0,
        }
    }

    /// Set one idle threshold. # C: O(1)
    pub fn set_idle_control(&self, k: super::knobs::Knob, value: u64) {
        let target = match k {
            super::knobs::Knob::IdleInterval => &self.idle_interval,
            super::knobs::Knob::DiscardIdleInterval => &self.discard_idle_interval,
            super::knobs::Knob::GcIdleInterval => &self.gc_idle_interval,
            _ => return,
        };
        target.store(value, Ordering::Release);
        self.gc.lock().gc_wake = true;
        self.dcc.lock().wake = true;
        self.waits.wake_gc();
        self.waits.wake_discard();
    }
}

#[cfg(test)]
mod tests {
    use super::FlushControl;

    #[test]
    fn a_flush_arriving_during_io_waits_for_the_next_barrier() {
        let mut f = FlushControl::new();
        let first_seen = f.generation + u64::from(f.inflight);
        f.pending = 1;
        f.inflight = true;
        let follower_seen = f.generation + u64::from(f.inflight);
        assert_ne!(first_seen, follower_seen);
        f.pending |= 2;
        f.inflight = false;
        f.generation += 1;
        assert_eq!(f.generation, follower_seen);
        assert_ne!(f.generation, first_seen);
    }
}
