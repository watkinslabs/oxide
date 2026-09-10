//! Production adapters; scheduler and task lookup are hosted seams.
#[path="../ready.rs"]mod ready;
#[path="../wait_live.rs"]pub(crate) mod wait_live;
#[path="../../user_input/queue_status.rs"]pub(crate) mod status;
mod live {
    pub(super) fn with_entry<R>(f:impl FnOnce(&mut crate::GuiEntry,u64)->R)->Option<R>{
        crate::owner::with_entry(|entry|f(entry,2))
    }
}
