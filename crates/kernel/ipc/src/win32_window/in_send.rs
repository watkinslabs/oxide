//! In-send-message state: what the thread-state class reports about the
//! message a thread is receiving from another thread.
//!
//! A thread that is not running a window procedure for a message another
//! thread sent reports no send. A thread inside such a procedure reports a
//! send until it has replied, and a replied send keeps the send bit.

/// The thread is not processing a message sent from elsewhere.
pub const ISMEX_NOSEND: u32 = 0x0000_0000;
/// The thread is processing a sent message that awaits a result.
pub const ISMEX_SEND: u32 = 0x0000_0001;
/// The thread is processing a sent message that takes no result.
pub const ISMEX_NOTIFY: u32 = 0x0000_0002;
/// The thread is processing a sent message whose result goes to a callback.
pub const ISMEX_CALLBACK: u32 = 0x0000_0004;
/// The result of the message being processed has already been sent back.
pub const ISMEX_REPLIED: u32 = 0x0000_0008;

/// The send a thread is receiving, as the thread-state class describes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedSend {
    /// The sender is a different thread; a thread that sends to itself calls
    /// its own window procedure and receives nothing.
    pub inter_thread: bool,
    /// The result has already been handed back to the sender.
    pub replied: bool,
}

/// Flags for the receive state of one thread. # C: O(1)
pub const fn receive_flags(received: Option<ReceivedSend>) -> u32 {
    let Some(received) = received else { return ISMEX_NOSEND; };
    if !received.inter_thread { return ISMEX_NOSEND; }
    ISMEX_SEND | if received.replied { ISMEX_REPLIED } else { 0 }
}

#[cfg(test)]
#[path = "tests/in_send.rs"]
mod tests;
