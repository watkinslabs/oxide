// POSIX session / process-group work fns against the real global registry:
// success paths, every errno in `sched::session::setpgid`'s ladder and the
// order they fire in, the pid==0/pgid==0 aliases, session-leader and
// cross-session cases, and `personality(2)`'s query form.
//
// Hosted fixtures have no vtgid stamped, so `process_vpid` falls back to the
// internal tgid and `lookup_in_namespace`'s initial-namespace shortcut resolves
// tids directly — the tid IS the pid for these tests.

use super::common::registry_test_lock;
use crate::personality;
use crate::session;
use crate::task::{SchedClass, Task};
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use syscall::errno::Errno;

fn proc(tid: u32) -> Arc<Task> {
    Arc::new(Task::new(tid, "p", SchedClass::Normal { weight: 1024 }))
}

/// One published process: its own thread group, its own pgrp+session, no parent.
fn published(tid: u32) -> Arc<Task> {
    let t = proc(tid);
    crate::registry::insert(&t);
    t
}

/// A child of `parent`, published, inheriting the parent's pgrp+session exactly
/// as `sys_clone` does.
fn child_of(parent: &Arc<Task>, tid: u32) -> Arc<Task> {
    let c = proc(tid);
    c.parent_tid.store(parent.tid, Ordering::Release);
    c.set_pgrp(parent.pgrp());
    c.set_session(parent.session());
    crate::registry::insert(&c);
    c
}

/// A second thread inside `leader`'s process (Linux CLONE_THREAD).
fn thread_in(leader: &Arc<Task>, tid: u32) -> Arc<Task> {
    let mut t = Task::new(tid, "t", SchedClass::Normal { weight: 1024 });
    t.join_thread_group(Arc::clone(&leader.thread_group));
    t.tgid.store(leader.tid, Ordering::Release);
    let t = Arc::new(t);
    crate::registry::insert(&t);
    t
}


fn tty_inode(ino: u64) -> vfs::InodeRef {
    vfs::InodeBuilder::new(ino, vfs::S_IFCHR | TTY_MODE,
        Arc::new(vfs::DefaultInodeOps), Arc::new(vfs::DefaultFileOps)).build()
}

/// `0600` — the permission bits a terminal device carries.
const TTY_MODE: u32 = 0o600;


#[path = "tests/setpgid.rs"]
mod setpgid;
#[path = "tests/queries.rs"]
mod queries;
#[path = "tests/terminal.rs"]
mod terminal;
#[path = "tests/setsid.rs"]
mod setsid;
#[path = "tests/ppid_personality.rs"]
mod ppid_personality;

