use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use namespace_identity::{Namespace, NamespaceKind, NamespaceRef};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::PollSubscribers;

use crate::Task;

/// Canonical PID identity retained independently of a task allocation.
pub struct PidIdentity {
    pub tid: u32,
    mappings: Spinlock<Option<Box<[PidMapping]>>, TaskListClass>,
    group_leader: AtomicBool,
    task: Spinlock<Option<Weak<Task>>, TaskListClass>,
    task_exited: AtomicBool,
    group_exited: AtomicBool,
    reaped: AtomicBool,
    exit_retired: AtomicBool,
    poll: Arc<PollSubscribers>,
    info: Spinlock<Option<PidInfo>, TaskListClass>,
}

struct PidMapping {
    namespace: Weak<Namespace>,
    nr: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PidMappingError {
    AlreadyConfigured,
    Empty,
    InvalidNumber,
    NamespaceKind,
    Ancestry,
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
        }
    }

    /// Publish immutable inner-to-outer PID mappings before task publication.
    /// `numbers[0]` belongs to `namespace`; each following number belongs to
    /// its exact parent. Only weak owners are retained. # C: O(depth)
    pub fn configure_mappings(&self, namespace: &NamespaceRef, numbers: &[u32])
        -> Result<(), PidMappingError>
    {
        if namespace.kind() != NamespaceKind::Pid { return Err(PidMappingError::NamespaceKind); }
        if numbers.is_empty() { return Err(PidMappingError::Empty); }
        if numbers.iter().any(|nr| *nr == 0) { return Err(PidMappingError::InvalidNumber); }
        let mut owner = Some(Arc::clone(namespace));
        let mut mappings = Vec::with_capacity(numbers.len());
        for nr in numbers {
            let Some(current) = owner.take() else { return Err(PidMappingError::Ancestry); };
            mappings.push(PidMapping { namespace: Arc::downgrade(&current), nr: *nr });
            owner = current.parent();
        }
        if owner.is_some() { return Err(PidMappingError::Ancestry); }
        let mut slot = self.mappings.lock();
        if slot.is_some() { return Err(PidMappingError::AlreadyConfigured); }
        *slot = Some(mappings.into_boxed_slice());
        Ok(())
    }

    /// Innermost live PID namespace ID for legacy numeric adapters. # C: O(1)
    pub fn namespace_id(&self) -> u64 {
        self.mappings.lock().as_ref()
            .and_then(|mappings| mappings.first())
            .and_then(|mapping| mapping.namespace.upgrade())
            .map(|namespace| namespace.id().as_u64())
            .unwrap_or(u64::MAX)
    }

    /// Namespace-visible thread number for one exact live namespace owner.
    /// # C: O(depth)
    pub fn visible_tid(&self, namespace: &NamespaceRef) -> Option<u32> {
        self.mappings.lock().as_ref()?.iter().find_map(|mapping| {
            let owner = mapping.namespace.upgrade()?;
            if Arc::ptr_eq(&owner, namespace) { Some(mapping.nr) } else { None }
        })
    }

    /// Whether immutable PID mappings were published. # C: O(1)
    pub fn mappings_configured(&self) -> bool {
        self.mappings.lock().is_some()
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

    /// Claim the one scheduler retirement for this identity. # C: O(1)
    pub fn claim_exit_retirement(&self) -> bool {
        !self.exit_retired.swap(true, Ordering::AcqRel)
    }
}

fn snapshot_task(task: &Task) -> PidInfo {
    PidInfo {
        pid: task.vtid.load(Ordering::Acquire),
        tgid: task.vtgid.load(Ordering::Acquire),
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
