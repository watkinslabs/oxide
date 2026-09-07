//! Kernel binding: job calls resolve their device context and report the null
//! print driver's result; the spool poll waits before reporting no message.
use super::{Call, MAX_ARGUMENTS, SPOOL_POLL_MS, argument_count, failure};
use crate::nt_gdi::dc_state::with_state;
use ipc::win32_gdi::{INIT_SPOOL_RESULT, SPOOL_MESSAGE_RESULT, SP_ERROR};

/// # C: canonical owner lookup, plus one bounded wait for the spool poll
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    let count = argument_count(ordinal)?;
    let Some(full) = crate::nt_wine_window::raw_gather::gather(args, count) else { return Some(failure(ordinal)); };
    super::route(ordinal, &full[..count.min(MAX_ARGUMENTS)], execute)
}

/// One nanosecond in each millisecond of the poll interval.
const NS_PER_MS: u64 = 1_000_000;

/// Wait out one poll interval without spinning. The wait is not alertable: no
/// message arrives to end it early. # C: one timed sleep
fn wait_out_poll() {
    let Some(current) = sched::live::current() else { return; };
    let table = current.thread_group.nt_handles();
    let deadline = timekeeper::monotonic_ns().saturating_add(SPOOL_POLL_MS.saturating_mul(NS_PER_MS));
    // SAFETY: wait_event_interruptible_until parks the calling task on the
    // process handle-table wait list until the deadline; no borrow outlives it.
    let _ = unsafe { sched::live::wait_event_interruptible_until(table.waiters(), deadline, timekeeper::monotonic_ns, || false) };
}

fn execute(call: Call) -> u64 {
    match call {
        Call::Job { dc, driver_result } => with_state(|state| Ok(state.print_job_result(dc, driver_result)))
            .unwrap_or(SP_ERROR) as i64 as u64,
        Call::StartDoc { dc, doc } => {
            // The document record is read before the job runs; a record the
            // caller cannot supply fails the job rather than starting one.
            if doc == 0 || uaccess::get_user_u32(doc).is_err() { return SP_ERROR as i64 as u64; }
            with_state(|state| Ok(state.print_job_result(dc, ipc::win32_gdi::JOB_RESULT)))
                .unwrap_or(SP_ERROR) as i64 as u64
        }
        Call::ExtEscape { dc } => with_state(|state| Ok(state.ext_escape(dc)))
            .unwrap_or(ipc::win32_gdi::EXT_ESCAPE_RESULT) as i64 as u64,
        Call::InitSpool => u64::from(INIT_SPOOL_RESULT),
        Call::SpoolMessage => {
            // A spooler polling in a loop must not spin: the reference waits
            // out the poll interval before reporting that no message arrived.
            wait_out_poll();
            u64::from(SPOOL_MESSAGE_RESULT)
        }
    }
}
