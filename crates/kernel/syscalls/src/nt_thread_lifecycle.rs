//! Canonical Task handle publication; tests exercise the real object table.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use sched::{Task, nt_object::{NtHandle, NtHandleTable}};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublishError { NoMemory, Writeback }

/// Failed native publication must allow the existing pthread to finish cleanup. # C: O(1)
pub(crate) fn cancel_native_publication(child: &Task) {
    child.nt_suspend_count.store(0, Ordering::Release);
    child.nt_creation_pending.store(false, Ordering::Release);
}

/// Publish only after handle writeback; failed creation remains unwakeable.
/// `commit` completes canonical publication before clearing the creation gate.
/// Raw children need registry insertion/birth wake; native children already
/// belong to the Linux registry and only advance attachment readiness here.
/// This gate records publication only, never native libc attachment readiness.
/// # C: O(N_handles + N_tasks)
pub(crate) fn publish(
    child: &Arc<Task>, table: &NtHandleTable, access: u32, suspended: bool,
    write: impl FnOnce(NtHandle) -> Result<(), ()>, commit: impl FnOnce(&Arc<Task>),
    rollback: impl FnOnce(),
) -> Result<(), PublishError> {
    child.nt_creation_pending.store(true, Ordering::Release);
    // The exclusively-owned new child has no existing suspend requests.
    child.nt_suspend_count.store(u32::from(suspended), Ordering::Release);
    let Some(handle) = table.insert(table.new_thread(child.clone()), access) else {
        rollback();
        return Err(PublishError::NoMemory);
    };
    if write(handle).is_err() {
        let _ = table.close(handle);
        rollback();
        return Err(PublishError::Writeback);
    }
    commit(child);
    child.nt_creation_pending.store(false, Ordering::Release);
    Ok(())
}

#[cfg(test)]
#[path = "nt_thread_lifecycle/tests.rs"]
mod tests;
