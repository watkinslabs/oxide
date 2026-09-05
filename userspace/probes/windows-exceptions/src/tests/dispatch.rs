use super::*;
use proptest::prelude::*;

#[test]
fn canonical_special_codes_are_classified() {
    for code in [EXCEPTION_WINE_STUB, EXCEPTION_WINE_ASSERTION, EXCEPTION_WINE_NAME_THREAD, EXCEPTION_WINE_CXX] {
        assert_eq!(classify(code), ExceptionClass::WineInternal);
    }
    for code in [DBG_PRINTEXCEPTION_C, DBG_PRINTEXCEPTION_WIDE_C] {
        assert_eq!(classify(code), ExceptionClass::DebuggerNotification);
    }
    assert_eq!(classify(STATUS_ASSERTION_FAILURE), ExceptionClass::Assertion);
}

#[test]
fn application_faults_remain_application_class() {
    for code in [0x8000_0003, 0xc000_0005, 0xc000_001d, 0xc000_0094, 0xc000_00fd] {
        assert_eq!(classify(code), ExceptionClass::Application);
    }
}

#[test]
fn unknown_codes_are_not_promoted_to_special_handling() {
    for code in [0, 0x4000_0000, 0x8000_00ff, 0xc000_0fff, u32::MAX] {
        assert_eq!(classify(code), ExceptionClass::Unknown);
    }
}

#[test]
fn vectored_continue_execution_short_circuits_structured_handlers() {
    assert_eq!(dispatch(0, HandlerResult::ContinueExecution, HandlerResult::RaiseStatus(7)), Outcome::ContinueExecution);
}

#[test]
fn vectored_search_reaches_structured_execute_handler() {
    assert_eq!(dispatch(0, HandlerResult::ContinueSearch, HandlerResult::ExecuteHandler), Outcome::ContinueExecution);
}

#[test]
fn structured_continue_execution_is_preserved() {
    assert_eq!(dispatch(0, HandlerResult::ContinueSearch, HandlerResult::ContinueExecution), Outcome::ContinueExecution);
}

#[test]
fn two_search_results_forward_once_as_unhandled() {
    assert_eq!(dispatch(0, HandlerResult::ContinueSearch, HandlerResult::ContinueSearch), Outcome::ForwardUnhandled);
}

#[test]
fn structured_status_is_raised_instead_of_forwarded() {
    assert_eq!(dispatch(0, HandlerResult::ContinueSearch, HandlerResult::RaiseStatus(0xc000_0005)), Outcome::RaiseStatus(0xc000_0005));
}

#[test]
fn invalid_structured_disposition_has_canonical_status() {
    assert_eq!(dispatch(0, HandlerResult::ContinueSearch, HandlerResult::InvalidDisposition), Outcome::RaiseStatus(STATUS_INVALID_DISPOSITION));
}

#[test]
fn vectored_non_continue_results_do_not_prevent_structured_dispatch() {
    for result in [HandlerResult::ExecuteHandler, HandlerResult::InvalidDisposition, HandlerResult::RaiseStatus(9)] {
        assert_eq!(dispatch(0, result, HandlerResult::ExecuteHandler), Outcome::ContinueExecution);
    }
}

proptest! {
    #[test]
    fn search_is_the_only_pair_that_forwards(code: u32) {
        let outcome = dispatch(code, HandlerResult::ContinueSearch, HandlerResult::ContinueSearch);
        prop_assert_eq!(outcome, Outcome::ForwardUnhandled);
    }

    #[test]
    fn vectored_continue_always_wins(code: u32, status: u32) {
        prop_assert_eq!(dispatch(code, HandlerResult::ContinueExecution, HandlerResult::RaiseStatus(status)), Outcome::ContinueExecution);
    }
}
