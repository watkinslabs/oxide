use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::clone::CLONE_PIDFD;

pub(super) fn exec_guard(
    current: &sched::Task,
    thread: bool,
) -> Result<Option<sched::rwsem::RwSemReadGuard<'_, ()>>, Errno> {
    if !thread { return Ok(None); }
    current.thread_group.try_exec_update_read().map(Some).ok_or(Errno::Eagain)
}

pub(super) fn prepare_pidfd(
    current: &sched::Task,
    child: &Arc<sched::Task>,
    flags: u64,
    user_ptr: u64,
) -> Result<Option<pidfd::Prepared>, i64> {
    if flags & CLONE_PIDFD == 0 { return Ok(None); }
    // A CLONE_THREAD child's descriptor names the THREAD, not the process it
    // joined; anything else would hand back a descriptor for a task the caller
    // did not create.
    let options = pidfd::OpenOptions {
        thread: crate::clone_abi::pidfd_is_thread(flags),
        ..pidfd::OpenOptions::default()
    };
    let prepared = pidfd::prepare(current, Arc::clone(&child.pid), options)
        .map_err(open_error)?;
    let fd = prepared.fd().to_ne_bytes();
    uaccess::copy_to_user(user_ptr, &fd)
        .map_err(|_| -(Errno::Efault.as_i32() as i64))?;
    Ok(Some(prepared))
}

pub(super) fn commit(
    child: &Arc<sched::Task>,
    thread: bool,
    pidfd: Option<pidfd::Prepared>,
) {
    if thread { child.thread_group.commit_member(); }
    sched::live::publish_new_task(child);
    if let Some(prepared) = pidfd { prepared.commit(); }
    sched::live::wake_new_task(child);
}

/// Complete the post-publication vfork parent wait. # C: O(N_wakeups)
pub(super) fn finish(child: Arc<sched::Task>, vfork: bool, child_event_msg: u64) {
    if !vfork { drop(child); return; }
    let watch = Arc::clone(&child);
    drop(child);
    // SAFETY: process context; watch retains the child through completion.
    let completed = unsafe { sched::live::wait_for_vfork_done(&watch) };
    drop(watch);
    if completed {
        crate::ptrace::stop::ptrace_event(
            crate::s101_ptrace_uapi::EVENT_VFORK_DONE, child_event_msg);
    }
}

fn open_error(error: pidfd::OpenError) -> i64 {
    match error {
        pidfd::OpenError::BadFileTable => -(Errno::Ebadf.as_i32() as i64),
        pidfd::OpenError::Install(error) => -(error as i64),
        pidfd::OpenError::NotFound => -(Errno::Esrch.as_i32() as i64),
        pidfd::OpenError::NotLeader => -(Errno::Enoent.as_i32() as i64),
    }
}
