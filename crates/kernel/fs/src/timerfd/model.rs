//! Timerfd inode identity, clock domains, and wall-clock-step observation.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, Timer as TimerLockClass};
use vfs::{FileType, Ino, InodeBuilder, InodeRef, default_inode_ops, mk_mode};

use super::file::TimerfdFileOps;
use super::state::TimerfdState;

#[cfg(target_os = "oxide-kernel")]
use sched::live::wait_list::WaitList;

#[cfg(not(target_os = "oxide-kernel"))]
pub(super) struct WaitList;

#[cfg(not(target_os = "oxide-kernel"))]
impl WaitList {
    pub(super) const fn new() -> Self { Self }
    pub(super) fn wake_all(&self) {}
    // SAFETY: hosted tests do not install a live scheduler or invoke blocking reads.
    pub(super) unsafe fn park_interruptible_with_deadline(&self, _deadline_ns: u64) {
        unreachable!("timerfd wait under hosted");
    }
}

/// timerfd's reserved inode-number range. bpf minted from this same base until
/// it was moved off; the range now says who owns it and the build fails if a
/// second owner claims it.
use vfs::pseudo_ino::TIMERFD as INO_REGION;

pub(super) const CLOCK_REALTIME:       u64 = 0;
pub(super) const CLOCK_MONOTONIC:      u64 = 1;
pub(super) const CLOCK_BOOTTIME:       u64 = 7;
pub(super) const CLOCK_REALTIME_ALARM: u64 = 8;
pub(super) const CLOCK_BOOTTIME_ALARM: u64 = 9;

/// Weak clock-step observers. The inode's `i_private` remains the sole owner
/// and identity; this list neither retains closed timerfds nor carries state.
static CLOCK_CANCEL_WATCHERS: Spinlock<Vec<Weak<TimerfdData>>, TimerLockClass>
    = Spinlock::new(Vec::new());
static NEXT_TIMERFD_ID: AtomicU32 = AtomicU32::new(0);

/// Per-inode timerfd state (Linux `i_private`). # C: O(1)
pub(super) struct TimerfdData {
    #[cfg(any(test, feature = "debug-desktop", feature = "debug-mutter-timer-verbose"))]
    pub(super) id:           u32,
    pub(super) clockid:      u64,
    pub(super) state:             Spinlock<TimerfdState, TimerLockClass>,
    pub(super) read_waiters:      WaitList,
    pub(super) poll_subscribers:  Arc<vfs::PollSubscribers>,
}

/// Read the host monotonic clock. # C: O(1)
#[inline]
pub(super) fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Test whether `clockid` is accepted by timerfd_create. # C: O(1)
pub(super) fn timerfd_clock_known(clockid: u64) -> bool {
    matches!(clockid, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME
        | CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM)
}

/// Test whether a timer uses the realtime clock family. # C: O(1)
pub(super) fn timerfd_realtime_clock(clockid: u64) -> bool {
    matches!(clockid, CLOCK_REALTIME | CLOCK_REALTIME_ALARM)
}

/// Test whether a timer uses an alarm clock. # C: O(1)
pub(super) fn timerfd_alarm_clock(clockid: u64) -> bool {
    matches!(clockid, CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM)
}

/// Select the time-namespace clock for an absolute timer. # C: O(1)
pub(super) fn timerfd_namespace_clock(clockid: u64) -> Option<nscg::time_ns::TimeNsClock> {
    match clockid {
        CLOCK_MONOTONIC => Some(nscg::time_ns::TimeNsClock::Monotonic),
        CLOCK_BOOTTIME | CLOCK_BOOTTIME_ALARM => Some(nscg::time_ns::TimeNsClock::Boottime),
        _ => None,
    }
}

/// Project an absolute realtime expiry into the monotonic park domain. # C: O(1)
pub(super) fn realtime_deadline(value: u64, now_mono: u64, now_real: u64) -> u64 {
    if value <= now_real {
        now_mono
    } else {
        now_mono.saturating_add(value - now_real).min(syscall::time::KTIME_MAX_NS)
    }
}

/// Build a monotonic expiry from relative or absolute input. # C: O(1)
pub(super) fn monotonic_deadline_from_value(flags: u64, value: u64, now_mono: u64) -> u64 {
    if value == 0 { return 0; }
    if (flags & super::uapi::TFD_TIMER_ABSTIME) == 0 {
        return now_mono.saturating_add(value).min(syscall::time::KTIME_MAX_NS);
    }
    value
}

/// Build a timerfd pseudo-inode with sole state ownership in `i_private`.
/// # C: O(N_timerfds) to prune the weak observer list
pub(super) fn make_timerfd_inode(clockid: u64) -> InodeRef {
    let id = NEXT_TIMERFD_ID.fetch_add(1, Ordering::Relaxed);
    let poll_subscribers = Arc::new(vfs::PollSubscribers::new());
    let data = Arc::new(TimerfdData {
        #[cfg(any(test, feature = "debug-desktop", feature = "debug-mutter-timer-verbose"))]
        id,
        clockid,
        state: Spinlock::new(TimerfdState::new(
            sched::clock::realtime_change_generation(),
        )),
        read_waiters: WaitList::new(),
        poll_subscribers: Arc::clone(&poll_subscribers),
    });
    {
        let mut watchers = CLOCK_CANCEL_WATCHERS.lock();
        watchers.retain(|watcher| watcher.strong_count() != 0);
        watchers.push(Arc::downgrade(&data));
    }
    InodeBuilder::new(INO_REGION.at(id as Ino),
        mk_mode(FileType::CharDev, 0), default_inode_ops(), Arc::new(TimerfdFileOps))
        .private(data)
        .poll_subs_arc(poll_subscribers)
        .build()
}

/// Wake live timerfds after a realtime clock step without owning their state.
/// The boundary was sampled before the timekeeper mutation, so a delayed weak
/// observer walk cannot manufacture an old-domain expiration.
/// # C: O(N_timerfds)
pub(super) fn timerfd_clock_was_set(step_mono_ns: u64) {
    let live: Vec<Arc<TimerfdData>> = {
        let mut watchers = CLOCK_CANCEL_WATCHERS.lock();
        watchers.retain(|watcher| watcher.strong_count() != 0);
        watchers.iter().filter_map(Weak::upgrade).collect()
    };
    let generation = sched::clock::realtime_change_generation();
    for timerfd in live {
        let now_mono = monotonic_ns();
        let now_real = vfs::inode_times::realtime_now_ns();
        let wake = {
            let mut state = timerfd.state.lock();
            let canceled = state.note_clock_was_set(
                generation,
                step_mono_ns,
                now_mono,
                now_real,
            );
            canceled || state.ticks != 0
                || (state.realtime_absolute && state.expiry_ns != 0)
        };
        if !wake { continue; }
        timerfd.read_waiters.wake_all();
        timerfd.poll_subscribers.notify_mask(vfs::POLL_IN);
    }
}

/// Install the timerfd observer in the scheduler's canonical clock-step path.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn install_clock_was_set_hook() {
    sched::timers::install_clock_was_set_hook(timerfd_clock_was_set);
}
