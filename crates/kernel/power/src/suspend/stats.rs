// Suspend statistics per `32a§11`, the `suspend_stats` attribute group.
//
// A ring of the last two failures per class, exactly as the reference keeps
// them: the value of a failure record is naming what broke on the attempt
// before last, which a single slot loses the moment a retry also fails.

use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use sync::{Spinlock, TaskList as PowerListClass};

/// Failures retained per class.
pub const REC_FAILED: usize = 2;
/// Longest device name a failure record keeps.
pub const FAILED_DEV_NAME: usize = 40;

/// The step group a failure is attributed to. Discriminants are the reference's
/// ordering, and `Working` is "no failure".
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StatStep {
    Working = 0,
    Freeze = 1,
    Prepare = 2,
    Suspend = 3,
    SuspendLate = 4,
    SuspendNoirq = 5,
    ResumeNoirq = 6,
    ResumeEarly = 7,
    Resume = 8,
}

/// Number of per-step failure counters (every step but `Working`).
pub const NR_STEPS: usize = 8;

impl StatStep {
    /// Attribute-file name of this step's failure counter. # C: O(1)
    pub fn name(self) -> &'static str {
        match self {
            StatStep::Working      => "",
            StatStep::Freeze       => "freeze",
            StatStep::Prepare      => "prepare",
            StatStep::Suspend      => "suspend",
            StatStep::SuspendLate  => "suspend_late",
            StatStep::SuspendNoirq => "suspend_noirq",
            StatStep::ResumeNoirq  => "resume_noirq",
            StatStep::ResumeEarly  => "resume_early",
            StatStep::Resume       => "resume",
        }
    }

    /// Index into the per-step failure counters. `Working` has none.
    /// # C: O(1)
    pub fn index(self) -> Option<usize> {
        match self { StatStep::Working => None, other => Some(other as usize - 1) }
    }

    /// Step for a counter index. # C: O(1)
    pub fn from_index(i: usize) -> Option<StatStep> {
        Some(match i {
            0 => StatStep::Freeze, 1 => StatStep::Prepare, 2 => StatStep::Suspend,
            3 => StatStep::SuspendLate, 4 => StatStep::SuspendNoirq,
            5 => StatStep::ResumeNoirq, 6 => StatStep::ResumeEarly, 7 => StatStep::Resume,
            _ => return None,
        })
    }
}

/// A fixed-capacity device name, so a failure record needs no allocation on a
/// path that may be running with interrupts off.
#[derive(Copy, Clone)]
pub struct DevName { bytes: [u8; FAILED_DEV_NAME], len: usize }

impl DevName {
    /// The empty name. # C: O(1)
    pub const fn empty() -> Self { DevName { bytes: [0; FAILED_DEV_NAME], len: 0 } }
    /// `s` truncated to the record width. # C: O(n)
    pub fn new(s: &str) -> Self {
        let mut d = DevName::empty();
        for b in s.as_bytes() {
            if d.len == FAILED_DEV_NAME { break; }
            d.bytes[d.len] = *b; d.len += 1;
        }
        d
    }
    /// The recorded name. # C: O(1)
    pub fn as_str(&self) -> &str { core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("") }
}

/// Failure records that need a lock: the device-name ring.
struct FailedDevs { names: [DevName; REC_FAILED], next: usize }

/// The machine's suspend statistics.
pub struct SuspendStats {
    step_failures: [AtomicU32; NR_STEPS],
    success: AtomicU32,
    fail: AtomicU32,
    errno: [AtomicI32; REC_FAILED],
    next_errno: AtomicUsize,
    failed_steps: [AtomicU32; REC_FAILED],
    next_step: AtomicUsize,
    devs: Spinlock<FailedDevs, PowerListClass>,
    last_hw_sleep: AtomicU64,
    total_hw_sleep: AtomicU64,
    max_hw_sleep: AtomicU64,
}

/// The machine's statistics.
pub static STATS: SuspendStats = SuspendStats::new();

impl SuspendStats {
    /// Zeroed statistics. # C: O(1)
    pub const fn new() -> Self {
        SuspendStats {
            step_failures: [const { AtomicU32::new(0) }; NR_STEPS],
            success: AtomicU32::new(0),
            fail: AtomicU32::new(0),
            errno: [const { AtomicI32::new(0) }; REC_FAILED],
            next_errno: AtomicUsize::new(0),
            failed_steps: [const { AtomicU32::new(0) }; REC_FAILED],
            next_step: AtomicUsize::new(0),
            devs: Spinlock::new(FailedDevs { names: [DevName::empty(); REC_FAILED], next: 0 }),
            last_hw_sleep: AtomicU64::new(0),
            total_hw_sleep: AtomicU64::new(0),
            max_hw_sleep: AtomicU64::new(0),
        }
    }

    /// Record a step failure and bump that step's counter. # C: O(1)
    pub fn save_failed_step(&self, step: StatStep) {
        let Some(i) = step.index() else { return };
        self.step_failures[i].fetch_add(1, Ordering::SeqCst);
        let slot = self.next_step.fetch_add(1, Ordering::SeqCst) % REC_FAILED;
        self.failed_steps[slot].store(step as u32, Ordering::SeqCst);
    }

    /// Record the device whose callback failed. # C: O(n) in the name
    pub fn save_failed_dev(&self, name: &str) {
        let mut d = self.devs.lock();
        let slot = d.next % REC_FAILED;
        d.names[slot] = DevName::new(name);
        d.next = d.next.wrapping_add(1);
    }

    /// Record the outcome of one attempt. Zero counts as a success and records
    /// no errno, so a machine that always suspends keeps an empty errno ring.
    /// # C: O(1)
    pub fn save_errno(&self, err: i32) {
        if err == 0 { self.success.fetch_add(1, Ordering::SeqCst); return; }
        self.fail.fetch_add(1, Ordering::SeqCst);
        let slot = self.next_errno.fetch_add(1, Ordering::SeqCst) % REC_FAILED;
        self.errno[slot].store(err, Ordering::SeqCst);
    }

    /// Report firmware-measured sleep time. # C: O(1)
    pub fn report_hw_sleep(&self, t: u64) {
        self.last_hw_sleep.store(t, Ordering::SeqCst);
        self.total_hw_sleep.fetch_add(t, Ordering::SeqCst);
    }

    /// Report the deepest firmware-measured sleep achievable. # C: O(1)
    pub fn report_max_hw_sleep(&self, t: u64) { self.max_hw_sleep.store(t, Ordering::SeqCst); }

    /// Successful attempts. # C: O(1)
    pub fn success(&self) -> u32 { self.success.load(Ordering::SeqCst) }
    /// Failed attempts. # C: O(1)
    pub fn fail(&self) -> u32 { self.fail.load(Ordering::SeqCst) }
    /// Failures attributed to `step`. # C: O(1)
    pub fn step_failures(&self, step: StatStep) -> u32 {
        step.index().map_or(0, |i| self.step_failures[i].load(Ordering::SeqCst))
    }
    /// The most recent failing errno, zero when there has been none. # C: O(1)
    pub fn last_failed_errno(&self) -> i32 { self.errno[self.newest(&self.next_errno)].load(Ordering::SeqCst) }
    /// The most recent failing step. # C: O(1)
    pub fn last_failed_step(&self) -> StatStep {
        let raw = self.failed_steps[self.newest(&self.next_step)].load(Ordering::SeqCst);
        StatStep::from_index((raw as usize).wrapping_sub(1)).unwrap_or(StatStep::Working)
    }
    /// The most recent failing device name. # C: O(1)
    pub fn last_failed_dev(&self) -> DevName {
        let d = self.devs.lock();
        d.names[(d.next + REC_FAILED - 1) % REC_FAILED]
    }
    /// Firmware-measured sleep of the last attempt. # C: O(1)
    pub fn last_hw_sleep(&self) -> u64 { self.last_hw_sleep.load(Ordering::SeqCst) }
    /// Firmware-measured sleep since boot. # C: O(1)
    pub fn total_hw_sleep(&self) -> u64 { self.total_hw_sleep.load(Ordering::SeqCst) }
    /// Deepest firmware-measured sleep reported. # C: O(1)
    pub fn max_hw_sleep(&self) -> u64 { self.max_hw_sleep.load(Ordering::SeqCst) }

    fn newest(&self, next: &AtomicUsize) -> usize {
        (next.load(Ordering::SeqCst) + REC_FAILED - 1) % REC_FAILED
    }
}

#[cfg(test)]
#[path = "stats/tests.rs"]
mod tests;
