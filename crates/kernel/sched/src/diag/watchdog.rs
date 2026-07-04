use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::{SchedClass, TaskState};

use super::current_task;
use super::ring::switches;
#[cfg(feature = "debug-watchdog")]
use super::emit::{dump_tasks, report_lockup};

const STALL_NS: u64 = 10_000_000_000;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Beat {
    pub tid: u32,
    pub runnable: bool,
    pub switches: u64,
    pub now_ns: u64,
}

#[derive(Copy, Clone, Debug)]
pub struct WatchdogState {
    window_tid: u32,
    window_switches: u64,
    window_start_ns: u64,
    fired: bool,
    armed: bool,
}

impl WatchdogState {
    pub const fn new() -> Self {
        Self { window_tid: 0, window_switches: 0, window_start_ns: 0, fired: false, armed: false }
    }

    pub fn step(&mut self, b: Beat) -> Option<u64> {
        if !b.runnable {
            self.armed = false;
            self.fired = false;
            return None;
        }
        if !self.armed || b.tid != self.window_tid || b.switches != self.window_switches {
            self.window_tid = b.tid;
            self.window_switches = b.switches;
            self.window_start_ns = b.now_ns;
            self.fired = false;
            self.armed = true;
            return None;
        }
        let elapsed = b.now_ns.wrapping_sub(self.window_start_ns);
        if elapsed < STALL_NS || self.fired {
            return None;
        }
        self.fired = true;
        Some(elapsed / 1_000_000_000)
    }
}

static WD_TID: AtomicU32 = AtomicU32::new(0);
static WD_SWITCHES: AtomicU64 = AtomicU64::new(0);
static WD_START_NS: AtomicU64 = AtomicU64::new(0);
static WD_FIRED: AtomicBool = AtomicBool::new(false);
static WD_ARMED: AtomicBool = AtomicBool::new(false);

const NOPROG_NS: u64 = 40_000_000_000;
static WD_NOPROG_SW: AtomicU64 = AtomicU64::new(0);
static WD_NOPROG_NS: AtomicU64 = AtomicU64::new(0);
static WD_NOPROG_FIRED: AtomicBool = AtomicBool::new(false);

pub fn watchdog_tick(now_ns: u64) {
    let cur = current_task();
    let runnable = match cur {
        Some(t) => t.state() == TaskState::Runnable && !matches!(t.sched_class(), SchedClass::Idle),
        None => false,
    };
    let beat = Beat {
        tid: cur.map(|t| t.tid).unwrap_or(0),
        runnable,
        switches: switches(),
        now_ns,
    };

    let mut st = WatchdogState {
        window_tid: WD_TID.load(Ordering::Relaxed),
        window_switches: WD_SWITCHES.load(Ordering::Relaxed),
        window_start_ns: WD_START_NS.load(Ordering::Relaxed),
        fired: WD_FIRED.load(Ordering::Relaxed),
        armed: WD_ARMED.load(Ordering::Relaxed),
    };
    let fired = st.step(beat);
    WD_TID.store(st.window_tid, Ordering::Relaxed);
    WD_SWITCHES.store(st.window_switches, Ordering::Relaxed);
    WD_START_NS.store(st.window_start_ns, Ordering::Relaxed);
    WD_FIRED.store(st.fired, Ordering::Relaxed);
    WD_ARMED.store(st.armed, Ordering::Relaxed);

    if let Some(_secs) = fired {
        #[cfg(feature = "debug-watchdog")]
        report_lockup(_secs, beat.tid, cur);
    }

    let sw = beat.switches;
    let last_sw = WD_NOPROG_SW.load(Ordering::Relaxed);
    if sw != last_sw {
        WD_NOPROG_SW.store(sw, Ordering::Relaxed);
        WD_NOPROG_NS.store(now_ns, Ordering::Relaxed);
        WD_NOPROG_FIRED.store(false, Ordering::Relaxed);
    } else {
        let since = now_ns.wrapping_sub(WD_NOPROG_NS.load(Ordering::Relaxed));
        if since >= NOPROG_NS && !WD_NOPROG_FIRED.swap(true, Ordering::Relaxed) {
            #[cfg(feature = "debug-watchdog")]
            {
                klog::write_raw(b"\n[WATCHDOG] no-progress: 0 context switches for ");
                klog::write_dec_u64(since / 1_000_000_000);
                klog::write_raw(b"s (parked wedge?) task dump:\n");
                dump_tasks();
            }
        }
    }
}

#[cfg(test)]
pub(crate) const TEST_STALL_NS: u64 = STALL_NS;
