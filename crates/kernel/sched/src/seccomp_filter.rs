// One installed seccomp filter as it sits on a task's chain — Linux `struct
// seccomp_filter`.
//
// Owned by `sched` rather than `security` because the CHAIN lives on `Task`
// and `security` depends on `sched`, not the other way round. Only the shape
// is here; every rule about installing, running or reading a filter stays in
// `security::seccomp`.

use alloc::vec::Vec;

/// An installed filter: the verified classic-BPF program in the packed
/// one-instruction-per-u64 form the interpreter runs, plus the install-time
/// flags `PTRACE_SECCOMP_GET_METADATA` reports back.
///
/// The flags travel WITH the program rather than in a parallel array: a
/// second container keyed by position would silently disagree the moment a
/// chain is cloned across `fork`, `execve` or `SECCOMP_FILTER_FLAG_TSYNC`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeccompFilter {
    /// `filter->prog` — packed `struct sock_filter` words.
    pub prog:  Vec<u64>,
    /// The `SECCOMP_FILTER_FLAG_*` word this filter was installed with.
    pub flags: u64,
    /// Identity of the user-notification listener this filter was installed
    /// with, if any. The ID rather than the object: a chain is copied by value
    /// onto every thread `SECCOMP_FILTER_FLAG_TSYNC` reaches and every forked
    /// child, and all of those copies must reach the SAME listener. `security`
    /// owns the id -> listener mapping; this is the filter's half of it.
    pub listener: Option<u64>,
}

impl SeccompFilter {
    /// # C: O(1)
    pub fn new(prog: Vec<u64>, flags: u64) -> Self { Self { prog, flags, listener: None } }
    /// A filter whose `SECCOMP_RET_USER_NOTIF` returns reach `listener`.
    /// # C: O(1)
    pub fn with_listener(prog: Vec<u64>, flags: u64, listener: u64) -> Self {
        Self { prog, flags, listener: Some(listener) }
    }
    /// Instruction count — `filter->prog->len`. # C: O(1)
    pub fn len(&self) -> usize { self.prog.len() }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.prog.is_empty() }
}
