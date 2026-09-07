//! Raw print job, spooler and device escape ingress.
//!
//! No print driver is loaded, so each job call resolves its device context and
//! reports the null print driver's own result.

/// Begin a document.
pub(crate) const START_DOC: u64 = 0x128d;
/// End a document.
pub(crate) const END_DOC: u64 = 0x119b;
/// Begin a page.
pub(crate) const START_PAGE: u64 = 0x128e;
/// End a page.
pub(crate) const END_PAGE: u64 = 0x119d;
/// Abandon a document.
pub(crate) const ABORT_DOC: u64 = 0x1084;
/// Initialise the spooler.
pub(crate) const INIT_SPOOL: u64 = 0x1237;
/// Wait for a spooler message.
pub(crate) const GET_SPOOL_MESSAGE: u64 = 0x1220;
/// Send a device-specific escape.
pub(crate) const EXT_ESCAPE: u64 = 0x11c5;

const CALLS: &[(u64, usize)] = &[
    (ABORT_DOC, 1), (END_DOC, 1), (END_PAGE, 1), (EXT_ESCAPE, 8),
    (GET_SPOOL_MESSAGE, 4), (INIT_SPOOL, 0), (START_DOC, 4), (START_PAGE, 1),
];

/// # C: O(N_family_ordinals)
pub(crate) fn argument_count(ordinal: u64) -> Option<usize> {
    CALLS.iter().find(|entry| entry.0 == ordinal).map(|entry| entry.1)
}

/// The longest signature this family carries.
pub(crate) const MAX_ARGUMENTS: usize = 8;

/// The spooler poll the reference waits out before reporting no message, so a
/// spooler service polling in a loop does not spin.
pub(crate) const SPOOL_POLL_MS: u64 = 500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Call {
    /// A job call that resolves its device context and reports one driver result.
    Job { dc: u32, driver_result: i32 },
    /// A document start, which reads its document record before the job runs.
    StartDoc { dc: u32, doc: u64 },
    ExtEscape { dc: u32 },
    InitSpool,
    SpoolMessage,
}

/// # C: O(N_family_ordinals)
pub(crate) fn route(ordinal: u64, args: &[u64], execute: impl FnOnce(Call) -> u64) -> Option<u64> {
    argument_count(ordinal)?;
    Some(match decode(ordinal, args) { Some(call) => execute(call), None => failure(ordinal) })
}

/// A job call that cannot admit its handle reports the spooler error; a device
/// escape reports that it handled nothing. # C: O(1)
pub(crate) fn failure(ordinal: u64) -> u64 {
    if ordinal == EXT_ESCAPE { return ipc::win32_gdi::EXT_ESCAPE_RESULT as i64 as u64; }
    ipc::win32_gdi::SP_ERROR as i64 as u64
}

/// # C: O(1)
pub(crate) fn decode(ordinal: u64, args: &[u64]) -> Option<Call> {
    let dc = |index: usize| args.get(index).copied().and_then(|value| u32::try_from(value).ok());
    Some(match ordinal {
        START_DOC => Call::StartDoc { dc: dc(0)?, doc: *args.get(1)? },
        START_PAGE => Call::Job { dc: dc(0)?, driver_result: ipc::win32_gdi::START_PAGE_RESULT },
        END_DOC | END_PAGE | ABORT_DOC => Call::Job { dc: dc(0)?, driver_result: ipc::win32_gdi::JOB_RESULT },
        EXT_ESCAPE => Call::ExtEscape { dc: dc(0)? },
        INIT_SPOOL => Call::InitSpool,
        GET_SPOOL_MESSAGE => Call::SpoolMessage,
        _ => return None,
    })
}

#[cfg(target_os = "oxide-kernel")]
#[path = "print_raw/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/print_raw.rs"]
mod tests;
