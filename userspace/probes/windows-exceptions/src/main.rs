use windows_exceptions::{classify, dispatch, ExceptionClass, HandlerResult, Outcome};

fn main() {
    assert_eq!(classify(0x8000_0003), ExceptionClass::Application);
    assert_eq!(dispatch(0x8000_0003, HandlerResult::ContinueSearch, HandlerResult::ContinueSearch), Outcome::ForwardUnhandled);
    println!("windows-exceptions: PASS (code classification and dispatch ordering)");
}
