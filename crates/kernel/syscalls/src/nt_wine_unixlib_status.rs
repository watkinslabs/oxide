//! Status the runtime's private Unixlib query reports when the load produced
//! no callable table.
//!
//! The reference resolves a builtin module's Unix half in two steps and each
//! step has its own failure status. A module with no Unix library registered,
//! and one whose library is registered but cannot be opened, both report the
//! library as missing — the open failure is a warning, not a distinct status.
//! Only a library that opened yet published neither a call table nor an
//! initialization entry reports a missing entry point. A malformed-argument
//! status belongs to neither case: the arguments were well formed, the
//! library was not there.

/// What admitting one Unixlib image produced, as the query boundary sees it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum UnixlibOutcome {
    /// The image could not be admitted for want of memory.
    NoMemory,
    /// No such library, or one that will not open.
    NotLoadable,
    /// Opened, but publishes no callable table.
    NoCallableTable,
}

pub(crate) const STATUS_NO_MEMORY: u64 = 0xc000_0017;
pub(crate) const STATUS_DLL_NOT_FOUND: u64 = 0xc000_0135;
pub(crate) const STATUS_ENTRYPOINT_NOT_FOUND: u64 = 0xc000_0139;

/// The status the query answers with.
/// # C: O(1)
pub(crate) fn status(outcome: UnixlibOutcome) -> u64 {
    match outcome {
        UnixlibOutcome::NoMemory => STATUS_NO_MEMORY,
        UnixlibOutcome::NotLoadable => STATUS_DLL_NOT_FOUND,
        UnixlibOutcome::NoCallableTable => STATUS_ENTRYPOINT_NOT_FOUND,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_library_that_is_absent_and_one_that_will_not_open_report_the_same_status() {
        // Both leave the module with no Unix handle, and the query reports the
        // library as missing for either. Reporting a malformed argument here
        // told the caller its own request was wrong, which it was not.
        assert_eq!(status(UnixlibOutcome::NotLoadable), STATUS_DLL_NOT_FOUND);
        assert_ne!(status(UnixlibOutcome::NotLoadable), 0xc000_000d);
    }

    #[test]
    fn a_library_without_a_call_table_reports_a_missing_entry_point() {
        assert_eq!(status(UnixlibOutcome::NoCallableTable), STATUS_ENTRYPOINT_NOT_FOUND);
    }

    #[test]
    fn an_exhausted_allocation_keeps_its_own_status() {
        assert_eq!(status(UnixlibOutcome::NoMemory), STATUS_NO_MEMORY);
    }
}
