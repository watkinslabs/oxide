use super::*;
use ipc::win32_gdi::{EXT_ESCAPE_RESULT, JOB_RESULT, SP_ERROR, START_PAGE_RESULT};

#[test]
fn every_ordinal_this_family_owns_declares_its_windows_argument_count() {
    for (ordinal, count) in CALLS { assert_eq!(argument_count(*ordinal), Some(*count), "ordinal {ordinal:#x}"); }
    assert_eq!(argument_count(0x1234), None);
    assert!(CALLS.iter().all(|entry| entry.1 <= MAX_ARGUMENTS));
}

#[test]
fn only_the_page_start_reports_a_job_beginning_and_the_rest_report_none() {
    assert_eq!(decode(START_PAGE, &[7]), Some(Call::Job { dc: 7, driver_result: START_PAGE_RESULT }));
    for ordinal in [END_DOC, END_PAGE, ABORT_DOC] {
        assert_eq!(decode(ordinal, &[7]), Some(Call::Job { dc: 7, driver_result: JOB_RESULT }), "ordinal {ordinal:#x}");
    }
}

#[test]
fn the_document_start_keeps_its_record_pointer() {
    assert_eq!(decode(START_DOC, &[7, 0x1_0000_9000, 0, 0]), Some(Call::StartDoc { dc: 7, doc: 0x1_0000_9000 }));
}

#[test]
fn the_spooler_calls_carry_no_device_context_at_all() {
    assert_eq!(decode(INIT_SPOOL, &[]), Some(Call::InitSpool));
    assert_eq!(decode(GET_SPOOL_MESSAGE, &[0, 0, 0, 0]), Some(Call::SpoolMessage));
    assert_eq!(route(INIT_SPOOL, &[], |call| u64::from(call == Call::InitSpool)), Some(1));
}

#[test]
fn a_job_call_that_cannot_admit_its_handle_reports_the_spooler_error() {
    assert_eq!(route(START_PAGE, &[0x1_0000_0000], |_| 5), Some(SP_ERROR as i64 as u64));
    assert_eq!(failure(START_DOC), SP_ERROR as i64 as u64);
    // A device escape reports that it handled nothing, not a spooler error.
    assert_eq!(route(EXT_ESCAPE, &[0x1_0000_0000], |_| 5), Some(EXT_ESCAPE_RESULT as i64 as u64));
    assert_eq!(route(0x1234, &[7], |_| 5), None);
}

#[test]
fn the_escape_reads_only_the_device_context_it_resolves() {
    assert_eq!(decode(EXT_ESCAPE, &[7, 0x1000, 0, 4, 0, 0, 0, 0]), Some(Call::ExtEscape { dc: 7 }));
}

#[test]
fn the_spool_poll_matches_the_interval_that_keeps_a_polling_spooler_off_the_processor() {
    assert_eq!(SPOOL_POLL_MS, 500);
}
