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
}

impl SeccompFilter {
    /// # C: O(1)
    pub fn new(prog: Vec<u64>, flags: u64) -> Self { Self { prog, flags } }
    /// Instruction count — `filter->prog->len`. # C: O(1)
    pub fn len(&self) -> usize { self.prog.len() }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.prog.is_empty() }
}
