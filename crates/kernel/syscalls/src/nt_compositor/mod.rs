//! Module manifest: queue owns bounded transactions; stream owns framing;
//! binding owns process/socket lifetime; worker owns asynchronous socket I/O.
mod queue;
mod stream;
mod capability;
#[cfg(target_os = "oxide-kernel")]
pub(crate) mod caret;
pub use queue::{Completion, Queue, TransportError};
#[cfg(target_os = "oxide-kernel")]
mod binding;
#[cfg(target_os = "oxide-kernel")]
mod worker;
#[cfg(target_os = "oxide-kernel")]
pub use binding::{bind_service, disconnect, enqueue, enqueue_current,
    monitors, monitors_current, wait_completion_current, set_event_handler};
#[cfg(test)]
#[path = "tests/transport.rs"]
mod tests;
#[cfg(test)]
#[path = "tests/capability.rs"]
mod capability_tests;
