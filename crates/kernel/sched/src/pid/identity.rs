use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, Ordering};


use sync::{Spinlock, TaskList as TaskListClass};
use vfs::PollSubscribers;

use crate::Task;

/// Canonical PID identity retained independently of a task allocation.
pub struct PidIdentity {
    pub tid: u32,
    pub(super) mappings: Spinlock<Option<Box<[super::PidMapping]>>, TaskListClass>,
    group_leader: AtomicBool,
    task: Spinlock<Option<Weak<Task>>, TaskListClass>,
    task_exited: AtomicBool,
    group_exited: AtomicBool,
    reaped: AtomicBool,
    exit_retired: AtomicBool,
    poll: Arc<PollSubscribers>,
    info: Spinlock<Option<PidInfo>, TaskListClass>,
    coredump: Spinlock<Option<CoredumpRecord>, TaskListClass>,
}

/// The coredump verdict this identity's process reached, latched by the dump
/// path so a pidfd holder can still read it after the process is gone. Absent
/// until the process actually faced a dump decision — which is what separates
/// "did not crash" from "crashed and the dump was skipped".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoredumpRecord {
    /// `PIDFD_COREDUMP*` bits: whether a dump happened and under whose rights.
    pub mask:   u32,
    /// The signal that caused it.
    pub signal: u32,
    /// The wait-encoded exit code the dump was taken at.
    pub code:   u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PidInfo {
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub ruid: u32,
    pub rgid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub exit_code: i32,
}

impl PidIdentity {
    /// Allocate an identity for a new thread-group leader. # C: O(1)
    pub fn new(tid: u32) -> Self {
        Self {
            tid,
            mappings: Spinlock::new(None),
            group_leader: AtomicBool::new(true),
            task: Spinlock::new(None),
            task_exited: AtomicBool::new(false),
            group_exited: AtomicBool::new(false),
            reaped: AtomicBool::new(false),
            exit_retired: AtomicBool::new(false),
            poll: Arc::new(PollSubscribers::new()),
            info: Spinlock::new(None),
            coredump: Spinlock::new(None),
        }
    }

    /// Attach the scheduler task represented by this identity. # C: O(1)
    pub fn attach(&self, task: &Arc<Task>) {
        *self.task.lock() = Some(Arc::downgrade(task));
    }

    /// Detach the task at `release_task` while retaining PID state. # C: O(1)
    pub fn detach(&self, task: &Task) {
        *self.info.lock() = Some(snapshot_task(task));
        *self.task.lock() = None;
        self.reaped.store(true, Ordering::Release);
        self.poll.notify_mask(vfs::POLL_IN | vfs::POLL_HUP);
    }

    /// Resolve the live or zombie task before `release_task`. # C: O(1)
    pub fn task(&self) -> Option<Arc<Task>> {
        self.task.lock().as_ref().and_then(Weak::upgrade)
    }

    /// Mark this PID as a nonleader before clone publication. # C: O(1)
    pub fn join_group(&self) {
        self.group_leader.store(false, Ordering::Release);
    }

    /// Whether this PID is the thread-group identity. # C: O(1)
    pub fn is_group_leader(&self) -> bool {
        self.group_leader.load(Ordering::Acquire)
    }

    /// Publish exact-thread exit. # C: O(N_subscribers)
    pub fn publish_task_exit(&self) {
        self.task_exited.store(true, Ordering::Release);
        if !self.is_group_leader() {
            self.poll.notify_mask(vfs::POLL_IN | vfs::POLL_RDNORM);
        }
    }

    /// Publish final-thread exit for the group identity. # C: O(N_subscribers)
    pub fn publish_group_exit(&self) {
        self.group_exited.store(true, Ordering::Release);
        self.poll.notify_mask(vfs::POLL_IN | vfs::POLL_RDNORM);
    }

    /// Linux pidfd poll readiness before reap. # C: O(1)
    pub fn exit_ready(&self) -> bool {
        if self.is_group_leader() {
            self.group_exited.load(Ordering::Acquire)
        } else {
            self.task_exited.load(Ordering::Acquire)
        }
    }

    /// Linux pidfd hangup state after `release_task`. # C: O(1)
    pub fn reaped(&self) -> bool {
        self.reaped.load(Ordering::Acquire)
    }

    /// Clone the exact wait source attached to pidfd inodes. # C: O(1)
    pub fn poll_subscribers(&self) -> Arc<PollSubscribers> {
        Arc::clone(&self.poll)
    }

    /// Snapshot PID/credential/exit information before or after reap. # C: O(N_tasks)
    pub fn info(&self) -> Option<PidInfo> {
        if let Some(task) = self.task() {
            Some(snapshot_task(&task))
        } else {
            *self.info.lock()
        }
    }

    /// Latch this process' coredump verdict (Linux `pidfs_coredump`). Called
    /// once, by the dump path, whether or not a dump is actually produced —
    /// a refusal is itself the answer a pidfd holder asks for. # C: O(1)
    pub fn record_coredump(&self, record: CoredumpRecord) {
        *self.coredump.lock() = Some(record);
    }

    /// The latched coredump verdict, `None` while this process never reached a
    /// dump decision. # C: O(1)
    pub fn coredump(&self) -> Option<CoredumpRecord> { *self.coredump.lock() }

    /// Claim the one scheduler retirement for this identity. # C: O(1)
    pub fn claim_exit_retirement(&self) -> bool {
        !self.exit_retired.swap(true, Ordering::AcqRel)
    }
}

impl Drop for PidIdentity {
    /// Return every number this identity took, so the namespaces that own them
    /// can name a later task with them. # C: O(depth log N_held)
    fn drop(&mut self) { self.release_numbers(); }
}

fn snapshot_task(task: &Task) -> PidInfo {
    // Every pid number here is answered in the READER's namespace, the way
    // `task_pid_vnr`/`task_tgid_vnr`/`task_ppid_vnr` are: these fields are
    // copied straight out to a caller that can only interpret them in its own
    // namespace. Reporting the task's OWN numbers handed an ancestor-namespace
    // reader a number naming a different process there, or none at all. `0`
    // stands for "the reader's namespace does not number this task", matching
    // the pid-number lookup that misses.
    let reader = crate::registry::reader_pid_ns();
    PidInfo {
        pid: crate::registry::vnr_in(task, &reader).unwrap_or(0),
        tgid: crate::registry::tgid_nr_in(task, &reader).unwrap_or(0),
        ppid: crate::registry::parent_vpid(task.tid) as u32,
        ruid: task.creds.ruid.load(Ordering::Acquire),
        rgid: task.creds.rgid.load(Ordering::Acquire),
        euid: task.creds.euid.load(Ordering::Acquire),
        egid: task.creds.egid.load(Ordering::Acquire),
        suid: task.creds.suid.load(Ordering::Acquire),
        sgid: task.creds.sgid.load(Ordering::Acquire),
        fsuid: task.creds.fsuid.load(Ordering::Acquire),
        fsgid: task.creds.fsgid.load(Ordering::Acquire),
        exit_code: task.exit_status.load(Ordering::Acquire),
    }
}
