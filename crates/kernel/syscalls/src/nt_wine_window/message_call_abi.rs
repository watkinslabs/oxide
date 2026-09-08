//! Seven-argument message-call boundary shared by raw ingress and hosted checks.
const ANSI_INDEX: usize = 6;
/// The message call's source-encoding argument is a four-byte Windows `BOOL`
/// occupying the low half of an eight-byte stack slot; the high half is
/// whatever the caller last left there. Widening the whole slot reports a
/// Unicode sender as ANSI, and the runtime then measures the sender's wide
/// string as a byte string: `"Untitled - Notepad"` arrives as `"U"`.
const ANSI_MASK: u64 = u32::MAX as u64;

pub(crate) fn tail(selector: u64, mut stack: impl FnMut(usize) -> Option<u64>) -> Option<(u32, bool)> {
    Some((selector as u32, stack(ANSI_INDEX)? & ANSI_MASK != 0))
}

#[cfg(test)]
#[path = "tests/message_call_abi.rs"]
mod tests;
