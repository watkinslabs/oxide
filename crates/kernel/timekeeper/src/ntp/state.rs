// Canonical NTP state plus the `do_adjtimex()` transaction (Linux
// `kernel/time/timekeeping.c` `__do_adjtimex` / `do_adjtimex`).
//
// Its own seqlock rather than a widening of `ClockState`: the clock state is
// copied by every `clock_gettime`, and NTP state is touched only by an NTP
// client and the once-per-tick advance. Both locks are taken in sequence,
// never nested.

use core::sync::atomic::{AtomicBool, Ordering};

use sync::{SeqLock, Timer as TimerLock};

use crate::platform::Irq;
use super::model::{AdjError, NtpState, Timex};
use super::uapi::{ADJ_NANO, ADJ_SETOFFSET, NSEC_PER_SEC, NSEC_PER_USEC};

static NTP: SeqLock<NtpState, TimerLock> = SeqLock::new(NtpState::INIT);
/// Cache of `NtpState::armed`: false until a mutating `adjtimex` mode lands,
/// and never cleared, so an undisciplined system pays one relaxed load per
/// tick instead of a seqlock read of the whole state.
static ARMED: AtomicBool = AtomicBool::new(false);

/// Outcome of a completed `adjtimex`. `state` is the `TIME_*` value the
/// syscall returns; `clock_stepped` means the wall clock jumped, so the caller
/// must run the absolute-deadline reprojection (`clock_was_set`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AdjOutcome { pub state: i32, pub clock_stepped: bool }

/// Snapshot the NTP state (diagnostics and tests). # C: O(1)
pub fn ntp_snapshot() -> NtpState { NTP.read() }

/// `do_adjtimex()` — validate, optionally step the wall clock, run the
/// discipline loop, and commit a changed TAI offset. `txc` is updated in place
/// with the resulting state, exactly as Linux writes back through the same
/// buffer it read.
/// # C: O(1)
pub fn do_adjtimex(txc: &mut Timex, capable: bool) -> Result<AdjOutcome, AdjError> {
    super::model::validate(txc, capable)?;

    // Sampled before any mutation, matching `ktime_get_real_ts64()` ahead of
    // the timekeeper lock: `txc.time` reports the clock as it was on entry,
    // not as ADJ_SETOFFSET left it.
    let now_ns = crate::state::realtime_ns();
    let ts_sec = (now_ns / NSEC_PER_SEC as u64) as i64;
    let ts_nsec = (now_ns % NSEC_PER_SEC as u64) as i64;

    let mut clock_stepped = false;
    if txc.modes & ADJ_SETOFFSET != 0 {
        let nsec = if txc.modes & ADJ_NANO != 0 { txc.time_usec }
                   else { txc.time_usec * NSEC_PER_USEC };
        let delta = i128::from(txc.time_sec) * i128::from(NSEC_PER_SEC) + i128::from(nsec);
        crate::state::inject_offset(delta).map_err(|_| AdjError::Inval)?;
        clock_stepped = true;
    }

    let orig_tai = crate::state::tai_offset();
    let mut tai = orig_tai;
    let state = NTP.write_with::<Irq, _>(|n| n.adjtimex(txc, ts_sec, ts_nsec, &mut tai));
    if NTP.read().armed { ARMED.store(true, Ordering::Release); }

    if tai != orig_tai {
        // `__timekeeping_set_tai_offset` + TK_CLOCK_WAS_SET. Out-of-range
        // values never reach here: `process_adjtimex_modes` ignores them.
        let _ = crate::state::set_tai_offset(tai);
        clock_stepped = true;
    }
    Ok(AdjOutcome { state, clock_stepped })
}

/// Per-tick NTP advance: run the leap/dispersion machine for each elapsed wall
/// second and apply the accumulated frequency/tick/adjtime slew to the wall
/// clock. Idempotent across CPUs — a second caller in the same instant sees no
/// elapsed time. A system no NTP client has touched returns on the first load.
/// # C: O(1)
/// # Ctx: any, including the timer IRQ
pub fn ntp_advance() {
    if !ARMED.load(Ordering::Acquire) { return; }
    let mono = crate::platform::monotonic_ns();
    let wall_sec = (crate::state::realtime_ns() / NSEC_PER_SEC as u64) as i64;
    let delta = NTP.write_with::<Irq, _>(|n| n.advance(mono, wall_sec));
    if delta != 0 { crate::state::slew_realtime(delta); }
}
