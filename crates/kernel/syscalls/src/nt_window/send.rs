// Module manifest: bounded sent work/replies; canonical owner execution and cancellation.
#[path="send/work.rs"] mod work;
#[path="send/live.rs"] mod live;
use work::Resume;
pub(crate) use work::{Queue,Reply,Outcome,Continuation,SendOutcome};
pub(crate) use live::{context_current,send_for_current,send_resumable_current,has_current,pump_current,wait_reply,complete_callback,handles_callback,cancel_thread,cancel_window};
