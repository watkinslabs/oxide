//! Seven-argument message-call boundary shared by raw ingress and hosted checks.
const ANSI_INDEX: usize = 6;

pub(crate) fn tail(selector: u64, mut stack: impl FnMut(usize) -> Option<u64>) -> Option<(u32, bool)> {
    Some((selector as u32, stack(ANSI_INDEX)? != 0))
}

#[cfg(test)]
#[path = "tests/message_call_abi.rs"]
mod tests;
