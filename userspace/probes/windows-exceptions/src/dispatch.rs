const STATUS_ASSERTION_FAILURE: u32 = 0xc000_0420;
const STATUS_INVALID_DISPOSITION: u32 = 0xc000_0026;

pub const EXCEPTION_WINE_STUB: u32 = 0x8000_0100;
pub const EXCEPTION_WINE_ASSERTION: u32 = 0x8000_0101;
pub const EXCEPTION_WINE_NAME_THREAD: u32 = 0x406d_1388;
pub const EXCEPTION_WINE_CXX: u32 = 0xe06d_7363;
pub const DBG_PRINTEXCEPTION_C: u32 = 0x4001_0006;
pub const DBG_PRINTEXCEPTION_WIDE_C: u32 = 0x4001_000a;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExceptionClass {
    WineInternal,
    DebuggerNotification,
    Assertion,
    Application,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandlerResult {
    ContinueExecution,
    ContinueSearch,
    ExecuteHandler,
    InvalidDisposition,
    RaiseStatus(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    ContinueExecution,
    RaiseStatus(u32),
    ForwardUnhandled,
}

/// Map one exception code to the diagnostics class used by dispatch.
/// # C: O(1)
pub const fn classify(code: u32) -> ExceptionClass {
    match code {
        EXCEPTION_WINE_STUB | EXCEPTION_WINE_ASSERTION | EXCEPTION_WINE_NAME_THREAD | EXCEPTION_WINE_CXX => ExceptionClass::WineInternal,
        DBG_PRINTEXCEPTION_C | DBG_PRINTEXCEPTION_WIDE_C => ExceptionClass::DebuggerNotification,
        STATUS_ASSERTION_FAILURE => ExceptionClass::Assertion,
        0x8000_0003 | 0xc000_0005 | 0xc000_001d | 0xc000_0094 | 0xc000_00fd => ExceptionClass::Application,
        _ => ExceptionClass::Unknown,
    }
}

/// Apply vectored, structured, and native forwarding precedence.
/// # C: O(1)
pub const fn dispatch(_code: u32, vectored: HandlerResult, structured: HandlerResult) -> Outcome {
    match vectored {
        HandlerResult::ContinueExecution => Outcome::ContinueExecution,
        HandlerResult::ContinueSearch => dispatch_structured(structured),
        HandlerResult::ExecuteHandler | HandlerResult::InvalidDisposition | HandlerResult::RaiseStatus(_) => dispatch_structured(structured),
    }
}

const fn dispatch_structured(result: HandlerResult) -> Outcome {
    match result {
        HandlerResult::ContinueExecution | HandlerResult::ExecuteHandler => Outcome::ContinueExecution,
        HandlerResult::ContinueSearch => Outcome::ForwardUnhandled,
        HandlerResult::InvalidDisposition => Outcome::RaiseStatus(STATUS_INVALID_DISPOSITION),
        HandlerResult::RaiseStatus(status) => Outcome::RaiseStatus(status),
    }
}

#[cfg(test)]
#[path = "tests/dispatch.rs"]
mod tests;
