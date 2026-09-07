// Module manifest: bounded sent work/replies; canonical owner execution and cancellation.
#[path="send/work.rs"] mod work;
#[path="send/live.rs"] mod live;
use work::Resume;
pub(crate) use work::{Queue,Reply,Outcome,Continuation,SendOutcome};
#[cfg(test)]
pub(crate) use live::context_current;
pub(crate) use live::{send_for_current,send_resumable_current,has_current,pump_current,wait_reply,cancel_thread,cancel_window};
// callbacks.rs (sole non-test consumer) is x86-64-only (NtCallbackReturn has
// no AArch64 continuation yet, KI-0703/KI-0704-class).
#[cfg(any(test, target_arch = "x86_64"))]
pub(crate) use live::{complete_callback,handles_callback};
