#![allow(unused_imports)]
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{fence, AtomicBool, AtomicI8, AtomicI32, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};
#[cfg(feature = "debug-task-fpu-provenance")]
use core::sync::atomic::AtomicUsize;

use sync::Spinlock;
use vmm::AddressSpace;

use crate::ARCH_CTX_SIZE;

use super::super::{ArchCtxBuf, ArchFpuBuf, Creds, PendingWake, SigActions, SignalPending, SchedClass, SyscallSnapshot, Task, TaskState, WaitState};
#[cfg(feature = "debug-watchdog")]
use super::super::WakeDiagPhase;
use super::super::namespaces::TaskNamespaces;
use crate::signum::Signum;

impl Task {
    /// Publish the syscall entry snapshot consumed by procfs. # C: O(1)
    pub fn record_syscall_snapshot(&self, snapshot: SyscallSnapshot) {
        *self.syscall_snapshot.lock() = snapshot;
    }

    /// Read the last syscall entry without borrowing an architectural frame.
    /// # C: O(1)
    pub fn syscall_snapshot(&self) -> SyscallSnapshot { *self.syscall_snapshot.lock() }

    /// Join an existing thread group while this task is still unpublished.
    /// # C: O(1)
    pub fn join_thread_group(&mut self, group: Arc<crate::thread_group::ThreadGroup>) {
        self.pid.join_group();
        crate::cputime_trace::join(self.tid, &group);
        // A fresh thread has nothing pending, so adopting the group's
        // `signalfd` readiness source loses nothing and is what puts every
        // thread of the process on ONE list (Linux `sighand->signalfd_wqh`).
        self.sigpending = SignalPending::with_poll(group.signalfd_poll());
        self.thread_group = group;
    }

    /// Process group id (Linux `task_pgrp`). Owned by the thread group, so
    /// every thread of the process reports and moves as one. # C: O(1)
    pub fn pgrp(&self) -> Arc<crate::pid::PidIdentity> { self.thread_group.pgrp() }

    /// Move this task's whole process into process group `pgid`. # C: O(1)
    pub fn set_pgrp(&self, pgrp: Arc<crate::pid::PidIdentity>) { self.thread_group.set_pgrp(pgrp); }

    /// Session id (Linux `task_session`). # C: O(1)
    pub fn session(&self) -> Arc<crate::pid::PidIdentity> { self.thread_group.session() }

    /// Move this task's whole process into session `sid`. # C: O(1)
    pub fn set_session(&self, session: Arc<crate::pid::PidIdentity>) {
        self.thread_group.set_session(session);
    }

    /// Hosted-fixture shorthand for constructing an otherwise unnumbered
    /// process-group identity. Production must move references, never ids.
    #[cfg(test)]
    pub fn set_pgid(&self, pgid: u32) {
        self.set_pgrp(Arc::new(crate::pid::PidIdentity::new(pgid)));
    }

    /// Hosted-fixture shorthand; see [`Self::set_pgid`].
    #[cfg(test)]
    pub fn set_sid(&self, sid: u32) {
        self.set_session(Arc::new(crate::pid::PidIdentity::new(sid)));
    }

    /// Initial-namespace fixture view of the pgrp identity.
    #[cfg(test)]
    pub fn pgid(&self) -> u32 { self.pgrp().tid }

    /// Initial-namespace fixture view of the session identity.
    #[cfg(test)]
    pub fn sid(&self) -> u32 { self.session().tid }

    /// Controlling terminal of this task's PROCESS (Linux
    /// `current->signal->tty`). # C: O(1); # Lk: TaskList
    pub fn ctty(&self) -> Option<vfs::InodeRef> { self.thread_group.ctty() }

    /// Inode number of the controlling terminal. # C: O(1); # Lk: TaskList
    pub fn ctty_ino(&self) -> Option<u64> { self.thread_group.ctty_ino() }

    /// Install or drop the whole process's controlling terminal.
    /// # C: O(1); # Lk: TaskList
    pub fn set_ctty(&self, tty: Option<vfs::InodeRef>) { self.thread_group.set_ctty(tty); }

    /// Claim the parked `CLONE_CHILD_SETTID` address, and the tid to store
    /// there, exactly once. Every later return to user mode sees `None`, so a
    /// task that has already published its tid never writes it again — which is
    /// what makes it safe to ask on EVERY return instead of only the first.
    /// # C: O(1)
    pub fn take_set_child_tid(&self) -> Option<(u64, u32)> {
        let addr = self.set_child_tid.swap(0, Ordering::AcqRel);
        if addr == 0 { return None; }
        Some((addr, self.security.vtid.load(Ordering::Acquire)))
    }

}
