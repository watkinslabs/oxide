//! Per-thread native NT user-callback continuation stack.

use alloc::vec::Vec;

const MAX_DEPTH: usize = 64;

/// Process-owned native callback registration. The variant carries the
/// schedule contract instead of exposing an untyped positional tuple to ABI
/// adapters.
pub enum RegistrationKind {
    Wait { object: u64, timeout_ms: u32, flags: u32 },
    TimerQueue,
    Timer { queue: u64, due_ms: u32, period_ms: u32, flags: u32, armed: bool },
    Pool { min_threads: u32, max_threads: u32, stack_reserve: u64, stack_commit: u64 },
    CleanupGroup,
    Work { pool: u64, environment: u64, queued: bool },
    Callback,
    NativeThreadFactory { return_entry: u64, pe_return: u64 },
}

pub struct Registration {
    pub token: u64,
    pub callback: u64,
    pub context: u64,
    pub kind: RegistrationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion { pub kind: u64, pub argument: u64 }

impl Completion { pub const NONE: Self = Self { kind: 0, argument: 0 }; }

/// Words of the architecture's user entry frame kept across a callback.
pub const REGISTER_WORDS: usize = 40;
/// Bytes of callee-saved SIMD/FP state kept across a callback: x86-64 keeps
/// xmm6-xmm15, MXCSR and the x87 control word; AArch64 keeps v8-v15, FPCR
/// and FPSR. The layout inside is the arch owner's contract.
pub const FP_BYTES: usize = 176;

/// Register state a user-mode callback must not be able to change in the
/// frame it interrupts: the complete integer entry frame plus the
/// callee-saved FP set. Native (Unix-ABI) callbacks clobber registers the
/// Windows ABI treats as preserved, so the continuation carries them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Preserved { pub regs: [u64; REGISTER_WORDS], pub fp: [u8; FP_BYTES] }

impl Preserved { pub const EMPTY: Self = Self { regs: [0; REGISTER_WORDS], fp: [0; FP_BYTES] }; }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame { pub rip: u64, pub rsp: u64, pub completion: Completion, pub preserved: Preserved }

pub struct Stack { frames: Vec<Frame> }

impl Stack {
    /// Create an empty callback continuation stack. # C: O(1)
    pub const fn new() -> Self { Self { frames: Vec::new() } }
    /// Push one continuation unless the bounded per-thread depth is full. # C: O(1) amortized
    pub fn push(&mut self, frame: Frame) -> bool {
        if self.frames.len() >= MAX_DEPTH || self.frames.try_reserve(1).is_err() { return false; }
        self.frames.push(frame); true
    }
    /// Remove the most recently suspended continuation. # C: O(1)
    pub fn pop(&mut self) -> Option<Frame> { self.frames.pop() }
    /// Return the number of suspended continuations. # C: O(1)
    pub fn len(&self) -> usize { self.frames.len() }
}

impl Default for Stack { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_frames_unwind_lifo() {
        let mut stack = Stack::new();
        assert!(stack.push(Frame { rip: 1, rsp: 2, completion: Completion::NONE, preserved: Preserved::EMPTY }));
        assert!(stack.push(Frame { rip: 3, rsp: 4, completion: Completion { kind: 7, argument: 8 }, preserved: Preserved::EMPTY }));
        assert_eq!(stack.len(), 2);
        assert_eq!(stack.pop(), Some(Frame { rip: 3, rsp: 4, completion: Completion { kind: 7, argument: 8 }, preserved: Preserved::EMPTY }));
        assert_eq!(stack.pop(), Some(Frame { rip: 1, rsp: 2, completion: Completion::NONE, preserved: Preserved::EMPTY }));
        assert_eq!(stack.pop(), None);
    }

    #[test]
    fn depth_is_bounded() {
        let mut stack = Stack::new();
        for value in 0..MAX_DEPTH { assert!(stack.push(Frame { rip: value as u64, rsp: value as u64, completion: Completion::NONE, preserved: Preserved::EMPTY })); }
        assert!(!stack.push(Frame { rip: MAX_DEPTH as u64, rsp: 0, completion: Completion::NONE, preserved: Preserved::EMPTY }));
    }
}
