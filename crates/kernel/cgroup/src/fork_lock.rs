use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, Ordering};

use vfs::{FileType, Inode, InodeBuilder, default_file_ops, default_inode_ops, mk_mode};

trait Held: Send {}
impl<T: Send> Held for T {}

static FORK_LOCK_INODE: AtomicPtr<Inode> = AtomicPtr::new(core::ptr::null_mut());

fn lock_inode() -> &'static Inode {
    let mut ptr = FORK_LOCK_INODE.load(Ordering::Acquire);
    if ptr.is_null() {
        let inode = InodeBuilder::new(vfs::get_next_ino() as u64, mk_mode(FileType::Regular, 0),
            default_inode_ops(), default_file_ops()).build();
        let candidate = Arc::into_raw(inode) as *mut Inode;
        match FORK_LOCK_INODE.compare_exchange(
            core::ptr::null_mut(), candidate, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => ptr = candidate,
            Err(winner) => {
                // SAFETY: candidate came from Arc::into_raw above and lost publication,
                // so reconstructing exactly one Arc releases that unpublished reference.
                drop(unsafe { Arc::from_raw(candidate) });
                ptr = winner;
            }
        }
    }
    // SAFETY: the published Arc reference is intentionally retained for kernel
    // lifetime, so the non-null inode pointer remains valid for every guard.
    unsafe { &*ptr }
}

/// Read-side fork transaction. Migration, exit, and hierarchy topology writers
/// wait until commit/cancel drops it; concurrent ordinary forks may prepare.
pub(crate) struct ForkTransaction { _held: Box<dyn Held> }

impl ForkTransaction {
    pub(crate) fn inherited() -> Self {
        Self { _held: Box::new(lock_inode().inode_lock_shared()) }
    }

}

/// Run one migration/exit/topology mutation after all prepared forks drain.
/// The VFS rwsem parks in kernel process context; no spinlock spans the wait.
pub(crate) fn with_write<R>(body: impl FnOnce() -> R) -> R {
    writer_waiting();
    let _held = lock_inode().inode_lock();
    writer_acquired();
    body()
}

#[cfg(test)]
static WRITERS_WAITING: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn writer_waiting() { WRITERS_WAITING.fetch_add(1, Ordering::AcqRel); }
#[cfg(not(test))]
fn writer_waiting() {}

#[cfg(test)]
fn writer_acquired() { WRITERS_WAITING.fetch_sub(1, Ordering::AcqRel); }
#[cfg(not(test))]
fn writer_acquired() {}
