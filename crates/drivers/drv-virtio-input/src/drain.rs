// Module manifest: `key_event` owns the shared keyboard pipeline;
// `queue` owns event-queue install/remove and softirq lifetime; `ring`
// owns used-ring drain/recycle; `status` owns q1 submission/reuse.

#![cfg(any(target_os = "oxide-kernel", test))]

mod key_event;
mod queue;
mod ring;
mod status;

pub use key_event::{handle_key_event, DRAINED_KEYS};
pub use queue::{install_eventq, poll_all, raise_drain, shutdown_eventq, uninstall_eventq};
pub use ring::DRAINED_EVENTS;
pub use status::{send_output_batch, send_status, send_status_batch, StatusError};

#[cfg(test)]
use queue::{
    owned_frames, release_handler_if_last, take_eventq, QueueCtx, CTXS, HANDLER_INSTALLED,
};

#[cfg(test)]
mod tests;
