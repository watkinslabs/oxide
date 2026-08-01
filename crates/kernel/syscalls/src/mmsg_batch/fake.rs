// A scripted socket for driving [`super::run`] hosted. Never compiled into a
// kernel image (`cfg(not(target_os = "oxide-kernel"))`); it exists so the unit
// tests AND the host-oracle differential corpus in
// `crates/kernel/syscalls/tests/conformance_mmsg.rs` drive the SAME production
// composition instead of each re-implementing the batch loop.
//
// Only the mechanical ABI steps are scripted. Every decision — the compat
// refusal, the timeout validation, the pending-error precedence, the entry
// flags, what ends a batch, what a partial batch reports — is made by
// `super`'s real code, which is the whole point.

use alloc::vec::Vec;

use syscall::errno::Errno;

use net::uapi::MSG_DONTWAIT;

use super::{BatchOps, timeout_total_ns};

/// A receive a real socket would have BLOCKED on. The fake cannot block, so it
/// answers with an errno no fixture here can otherwise produce: a batch that
/// reaches this is a batch that would have hung, and the errno it then latches
/// is the evidence.
pub const WOULD_BLOCK: i64 = -(Errno::Etimedout.as_i32() as i64);

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// One scripted entry outcome.
pub enum Entry {
    /// The receive delivered a message, and whether it carried urgent data.
    Got { oob: bool },
    /// The receive failed with this negative errno.
    Failed(i64),
}

/// A scripted socket. Build it, hand it to [`super::run`], read the record.
pub struct Fake {
    /// Timespec the caller supplied, exactly as it would arrive from user
    /// memory — `import_timeout` validates it with the real rule.
    pub timeout: Option<(i64, i64)>,
    /// The supplied timespec is unreadable.
    pub timeout_fault: bool,
    /// What `resolve` reports.
    pub resolve: Result<(), i64>,
    /// The socket's pending error, consumed by the first read of it.
    pub pending: i32,
    /// Scripted receive outcome per entry; a batch that walks past the end
    /// sees an empty queue — `EAGAIN` when it asked not to wait, and
    /// [`WOULD_BLOCK`] when it did not.
    pub entries: Vec<Entry>,
    /// Timeout left after each delivery; `None` = none supplied.
    pub remaining: Vec<Option<u64>>,
    /// `(index, negative errno)` — one entry whose length copyout faults.
    pub publish_fault: Option<(u64, i64)>,
    /// Per-entry flags each receive actually ran with.
    pub seen_flags: Vec<u64>,
    /// Errno latched as the socket's pending error, if any.
    pub latched: Option<i32>,
    /// Whether the remaining timeout was written back.
    pub copied_timeout: bool,
    /// Scripted entries the batch never reached.
    pub unreached: usize,
    /// Whether the descriptor was resolved.
    pub resolved: bool,
}

impl Fake {
    /// # C: O(entries)
    pub fn new(entries: Vec<Entry>) -> Self {
        let unreached = entries.len();
        Fake { timeout: None, timeout_fault: false, resolve: Ok(()), pending: 0, entries,
            remaining: Vec::new(), publish_fault: None, seen_flags: Vec::new(), latched: None,
            copied_timeout: false, unreached, resolved: false }
    }

    /// `count` queued messages and nothing more, the shape a nonblocking
    /// drain of a real socket queue sees. # C: O(count)
    pub fn queued(count: usize) -> Self {
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count { entries.push(Entry::Got { oob: false }); }
        Fake::new(entries)
    }
}

impl BatchOps for Fake {
    fn import_timeout(&mut self) -> Result<(), i64> {
        if self.timeout_fault { return Err(err(Errno::Efault)); }
        let Some((sec, nsec)) = self.timeout else { return Ok(()) };
        timeout_total_ns(sec, nsec).map(|_| ()).map_err(err)
    }

    fn resolve(&mut self) -> Result<(), i64> {
        self.resolved = self.resolve.is_ok();
        self.resolve
    }

    fn take_pending_error(&mut self) -> i32 { core::mem::take(&mut self.pending) }

    fn receive(&mut self, index: u64, flags: u64) -> i64 {
        self.seen_flags.push(flags);
        match self.entries.get(index as usize) {
            None if flags & MSG_DONTWAIT != 0 => -(Errno::Eagain.as_i32() as i64),
            None => WOULD_BLOCK,
            Some(entry) => {
                self.unreached -= 1;
                match entry { Entry::Failed(errno) => *errno, Entry::Got { .. } => 1 }
            }
        }
    }

    fn publish(&mut self, index: u64, _len: i64) -> Result<(), i64> {
        match self.publish_fault {
            Some((at, errno)) if at == index => Err(errno),
            _ => Ok(()),
        }
    }

    fn received_oob(&mut self, index: u64) -> bool {
        matches!(self.entries.get(index as usize), Some(Entry::Got { oob: true }))
    }

    fn timeout_left(&mut self) -> Option<u64> {
        self.remaining.get(self.seen_flags.len().saturating_sub(1)).copied().flatten()
    }

    fn latch_error(&mut self, errno: i32) { self.latched = Some(errno); }

    fn copy_timeout_back(&mut self) -> Result<(), i64> { self.copied_timeout = true; Ok(()) }
}

/// Run one scripted batch, returning its result and the fake it drove.
/// # C: O(entries)
pub fn drive(flags: u64, vlen: u64, mut fake: Fake) -> (i64, Fake) {
    let result = super::run_batch(&mut fake, flags, vlen);
    (result, fake)
}
