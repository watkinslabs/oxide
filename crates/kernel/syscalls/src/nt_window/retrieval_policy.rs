//! Per-thread nested retrieval continuations and raw message return encoding; 31fl§1.
use alloc::vec::Vec;
use syscall::nt::NtCall;
const MAX_RETRIEVALS: usize = 64;
const STATUS_PENDING: u64 = 0x103;
const WM_QUIT: u32 = 0x12;
const ERROR: u64 = u32::MAX as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Retrieval { pub tid: u64, pub call: NtCall, pub raw: bool }

pub(crate) fn push(stack: &mut Vec<Retrieval>, saved: Retrieval) -> bool {
    if saved.tid == 0 || stack.len() >= MAX_RETRIEVALS || stack.try_reserve(1).is_err() { return false; }
    stack.push(saved); true
}

pub(crate) fn pop(stack: &mut Vec<Retrieval>, tid: u64) -> Option<Retrieval> {
    let index = stack.iter().rposition(|saved| saved.tid == tid)?;
    Some(stack.remove(index))
}

pub(crate) fn cancel_thread(stack: &mut Vec<Retrieval>, tid: u64) { stack.retain(|saved| saved.tid != tid); }

pub(crate) fn raw_result(get: bool, status: u64, message: Option<u32>) -> u64 {
    if status == STATUS_PENDING { return status; }
    if status != 0 { return if get { ERROR } else { 0 }; }
    if !get { return 1; }
    match message { Some(WM_QUIT) => 0, Some(_) => 1, None => ERROR }
}

#[cfg(test)]
#[path = "tests/retrieval_policy.rs"]
mod tests;
