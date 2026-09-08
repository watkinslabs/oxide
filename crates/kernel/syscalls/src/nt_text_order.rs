// Module manifest: queue owns the order of one thread's kernel text work;
// live binds it to the current Task, the font backend and the paint end.
#[path = "nt_text_order/queue.rs"] mod queue;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use queue::{drive, Next, Owed, Queue, Run};
#[cfg(target_os = "oxide-kernel")]
#[path = "nt_text_order/live.rs"] mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::{advance_for_current, cancel_for_current, end_paint_for_current, submit_cells_for_current, submit_for_current};
