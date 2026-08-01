// The `SCHED_DEADLINE` half of `__sched_setscheduler`: what counts as a
// parameter change, the privilege gate an unprivileged caller cannot pass, and
// the admission decision that answers `EBUSY`.
//
// Ungated so the errno ORDER and the admission arithmetic are reachable from
// `cargo test`; the slot files and the runqueue commit stay thin.

use sched::deadline::bw::{self, BwChange, DL_BW};
use sched::deadline::DlParams;
use syscall::errno::Errno;

use crate::sched_attr::SchedAttr;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The reservation a request describes.
/// # C: O(1)
pub fn attr_params(attr: &SchedAttr) -> DlParams {
    DlParams::from_request(attr.runtime, attr.deadline, attr.period, attr.flags)
}

/// Would this request alter the task's reservation? A request that repeats the
/// task's own parameters commits nothing — and, crucially, is admitted without
/// consulting the ledger, so re-issuing them can never fail with `EBUSY`.
/// # C: O(1)
pub fn dl_param_changed(cur: &DlParams, attr: &SchedAttr) -> bool {
    let want = attr_params(attr);
    cur.runtime != want.runtime || cur.deadline != want.deadline
        || cur.period != want.period || cur.flags != want.flags
}

/// Is `span` — the set of CPUs the deadline class schedules over — wholly
/// inside `mask`? Shares its rule with `deadline::live::confined_below_span`,
/// which the cpuset writer consults.
///
/// Admission books a reservation against the whole span, so a task confined to
/// fewer CPUs than the span has a guarantee the ledger never checked. An
/// unprivileged caller is refused rather than admitted on a false premise.
/// # C: O(1)
pub fn affinity_covers_span(span: u64, mask: u64) -> bool { span & !mask == 0 }

/// The unprivileged-caller gate that runs after the parameter and permission
/// ladders: a deadline request is refused when the task cannot use the whole
/// span, or when the class has no bandwidth to give at all.
/// # C: O(1)
pub fn user_dl_allowed(span: u64, mask: u64, class_bw: u64) -> bool {
    class_bw != 0 && affinity_covers_span(span, mask)
}

/// Narrowing a deadline task's affinity below the span is refused: its
/// reservation was admitted against the span, and honouring a narrower mask
/// would quietly overcommit whatever is left.
/// # C: O(1)
pub fn setaffinity_allowed(is_dl: bool, span: u64, new_mask: u64) -> Result<(), i64> {
    if !is_dl { return Ok(()); }
    if affinity_covers_span(span, new_mask) { return Ok(()); }
    Err(err(Errno::Ebusy))
}

/// Decide what a request does to the admitted total, or refuse it.
///
/// `Err` is `-EBUSY` — the machine has no bandwidth left, which is a capacity
/// answer, not a permission or argument one.
/// # C: O(1)
pub fn admit(want_dl: bool, is_dl: bool, cur: &DlParams, want: &DlParams)
    -> Result<BwChange, i64>
{
    bw::plan(DL_BW.bw(), DL_BW.capacity(), DL_BW.total_bw(), want_dl, is_dl,
             cur.bw, want.bw, want.is_special() || cur.is_special())
        .map_err(|()| err(Errno::Ebusy))
}

/// Commit an admission plan to the ledger.
/// # C: O(1)
pub fn commit(change: BwChange) { DL_BW.apply(change); }

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "dl/tests.rs"]
mod tests;
