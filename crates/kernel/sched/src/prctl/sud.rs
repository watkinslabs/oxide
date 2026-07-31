// `prctl(PR_SET_SYSCALL_USER_DISPATCH, mode, offset, len, selector)` —
// syscall user dispatch.
//
// A task registers a code range plus a one-byte selector in its own memory.
// Every syscall issued from OUTSIDE the allowed range, while the selector
// byte reads BLOCK, is rolled back and reported to userspace as a catchable
// `SIGSYS` with `si_code == SYS_USER_DISPATCH` instead of being executed.
// Wine/FEX/Proton use it to emulate a foreign syscall ABI in-process.
//
// UNGATED on purpose: the mode ladder, the range inversion and the
// dispatch predicate are the whole contract, so they must be reachable from
// `cargo test` (`CLAUDE.md` phantom-test rule). The task-state binding lives
// in `dispatch.rs`; the per-syscall consumer lives in the syscall dispatch
// head, which is the only thing that makes the registration mean anything.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use syscall::errno::Errno;

use super::uapi::*;

/// A validated registration, in the SAME normalised form the per-syscall
/// predicate consumes: `INCLUSIVE_ON` is stored inverted so both modes share
/// one wrapping comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub on: bool,
    pub offset: u64,
    pub len: u64,
    pub selector: u64,
}

/// Linux `task_set_syscall_user_dispatch`'s argument ladder.
///
/// `EXCLUSIVE_ON` only rejects an overflowing range when `offset` is
/// non-zero (offset 0 with any length is the "whole address space is the
/// dispatcher" case). `INCLUSIVE_ON` rejects a zero length outright, then
/// INVERTS the range — storing `offset + len` and `-len` — so that the
/// single wrapping predicate `ip - offset < len` selects the INSIDE of the
/// requested window for one mode and the OUTSIDE for the other. Getting the
/// inversion wrong silently swaps "dispatch these syscalls" for "dispatch
/// every other syscall", which is a runaway SIGSYS loop rather than a
/// visible error.
/// # C: O(1)
pub fn classify_set(mode: u64, offset: u64, len: u64, selector: u64) -> Result<Config, Errno> {
    match mode {
        PR_SYS_DISPATCH_OFF => {
            if offset != 0 || len != 0 || selector != 0 { return Err(Errno::Einval); }
            Ok(Config { on: false, offset: 0, len: 0, selector: 0 })
        }
        PR_SYS_DISPATCH_EXCLUSIVE_ON => {
            if offset != 0 && offset.wrapping_add(len) <= offset { return Err(Errno::Einval); }
            Ok(Config { on: true, offset, len, selector })
        }
        PR_SYS_DISPATCH_INCLUSIVE_ON => {
            if len == 0 || offset.wrapping_add(len) <= offset { return Err(Errno::Einval); }
            Ok(Config {
                on: true,
                offset: offset.wrapping_add(len),
                len: len.wrapping_neg(),
                selector,
            })
        }
        _ => Err(Errno::Einval),
    }
}

/// Linux's `if (likely(instruction_pointer(regs) - sd->offset < sd->len))
/// return false;` — TRUE when the trapping PC sits in the range that is
/// exempt from dispatch. Wrapping arithmetic is load-bearing: it is what
/// makes the inverted `INCLUSIVE_ON` encoding select the complement.
/// # C: O(1)
pub fn pc_is_exempt(cfg: &Config, pc: u64) -> bool {
    pc.wrapping_sub(cfg.offset) < cfg.len
}

/// What the syscall dispatch head must do for one syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Execute the syscall normally.
    Run,
    /// Roll the syscall back and raise a catchable `SIGSYS`.
    Dispatch,
    /// The selector byte held a value that is neither ALLOW nor BLOCK: Linux
    /// `force_exit_sig(SIGSYS)` — an UNCATCHABLE kill, not a normal signal.
    KillSigsys,
    /// The selector could not be read: `force_exit_sig(SIGSEGV)`.
    KillSigsegv,
}

/// The per-syscall decision, given the trapping PC and the selector byte the
/// caller already read (`None` = the read faulted).
///
/// A registration with a NULL selector dispatches every syscall outside the
/// exempt range unconditionally — `if (likely(sd->selector))` skips the byte
/// check entirely, it does not treat a null selector as ALLOW.
/// # C: O(1)
pub fn decide(cfg: &Config, pc: u64, selector_byte: Option<u8>) -> Action {
    if !cfg.on { return Action::Run; }
    if pc_is_exempt(cfg, pc) { return Action::Run; }
    if cfg.selector != 0 {
        match selector_byte {
            None => return Action::KillSigsegv,
            Some(SYSCALL_DISPATCH_FILTER_ALLOW) => return Action::Run,
            Some(SYSCALL_DISPATCH_FILTER_BLOCK) => {}
            Some(_) => return Action::KillSigsys,
        }
    }
    Action::Dispatch
}

/// Live per-task registration. One `Task` field rather than five, so the
/// syscall-dispatch owner reads a single coherent record.
#[derive(Debug)]
pub struct SyscallUserDispatch {
    on: AtomicBool,
    offset: AtomicU64,
    len: AtomicU64,
    selector: AtomicU64,
    /// Linux `sd->on_dispatch`: set when a syscall was rolled back, so the
    /// syscall-EXIT work (tracepoints, ptrace exit stop, audit) is skipped
    /// for a call whose ABI the kernel never interpreted.
    on_dispatch: AtomicBool,
}

impl Default for SyscallUserDispatch { fn default() -> Self { Self::new() } }

impl SyscallUserDispatch {
    /// A task with dispatch off. # C: O(1)
    pub const fn new() -> Self {
        Self {
            on: AtomicBool::new(false),
            offset: AtomicU64::new(0),
            len: AtomicU64::new(0),
            selector: AtomicU64::new(0),
            on_dispatch: AtomicBool::new(false),
        }
    }

    /// Install a validated registration. # C: O(1)
    pub fn install(&self, cfg: &Config) {
        self.offset.store(cfg.offset, Ordering::Release);
        self.len.store(cfg.len, Ordering::Release);
        self.selector.store(cfg.selector, Ordering::Release);
        self.on_dispatch.store(false, Ordering::Release);
        self.on.store(cfg.on, Ordering::Release);
    }

    /// Snapshot for the per-syscall predicate. `None` when dispatch is off,
    /// which is the common case and costs one relaxed load. # C: O(1)
    pub fn armed(&self) -> Option<Config> {
        if !self.on.load(Ordering::Acquire) { return None; }
        Some(Config {
            on: true,
            offset: self.offset.load(Ordering::Acquire),
            len: self.len.load(Ordering::Acquire),
            selector: self.selector.load(Ordering::Acquire),
        })
    }

    /// Linux `clear_syscall_work_syscall_user_dispatch` — execve and a fresh
    /// fork child both start with dispatch OFF. # C: O(1)
    pub fn clear(&self) {
        self.on.store(false, Ordering::Release);
        self.on_dispatch.store(false, Ordering::Release);
    }

    /// Latch "this syscall was rolled back". # C: O(1)
    pub fn set_on_dispatch(&self) { self.on_dispatch.store(true, Ordering::Release); }

    /// Read-and-clear, matching Linux's syscall-exit-work arm. # C: O(1)
    pub fn take_on_dispatch(&self) -> bool { self.on_dispatch.swap(false, Ordering::AcqRel) }
}

#[cfg(test)]
#[path = "sud/tests.rs"]
mod tests;
