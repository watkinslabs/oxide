// Module manifest: `key_event` owns the shared keyboard pipeline;
// `queue` owns event-queue install/remove and softirq lifetime; `ring`
// owns used-ring drain/recycle.

#![cfg(any(target_os = "oxide-kernel", test))]

mod key_event;
mod queue;
mod ring;

pub use key_event::{handle_key_event, DRAINED_KEYS};
pub use queue::{install_eventq, poll_all, raise_drain, shutdown_eventq, uninstall_eventq};
pub use ring::DRAINED_EVENTS;

#[cfg(test)]
use queue::{release_handler_if_last, take_eventq, QueueCtx, CTXS, HANDLER_INSTALLED};

#[cfg(test)]
mod tests;
