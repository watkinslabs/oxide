// What a worker borrows to run one request as the task that submitted it.
//
// A worker thread has no address space and no descriptor table of its own. It
// installs the submitter's for the length of one request and gives them back
// afterwards, so a buffer address, a descriptor number and a permission check
// all mean on the worker exactly what they meant to the submitter. Anything
// less is not "asynchronous" — it is the wrong operation.
//
// The borrow is released on EVERY exit from a request, which is what the guard
// type is for: a worker that kept a dead task's address space installed would
// keep that whole address space alive and would resolve the NEXT request's
// user addresses through it.

use alloc::sync::Arc;

use vfs::FdTable;
use vmm::AddressSpace;

use crate::io_uring::personality::{CredSnapshot, CredsOverride};

/// The submitting task's execution context, captured once per ring at the
/// first async submission.
pub struct Owner {
    pub mm: Option<Arc<AddressSpace>>,
    pub fdt: Option<Arc<FdTable>>,
    pub creds: Option<Arc<CredSnapshot>>,
}

impl Owner {
    /// Capture the running task's context. # C: O(1)
    pub fn of_current() -> Arc<Self> {
        let Some(cur) = sched::live::current() else {
            return Arc::new(Self { mm: None, fdt: None, creds: None });
        };
        Arc::new(Self {
            mm: cur.clone_mm(),
            fdt: cur.clone_fd_table(),
            creds: crate::io_uring::personality::snapshot_current().map(Arc::new),
        })
    }
}

/// A context installed on the running worker for the length of one request.
/// Dropping it puts the worker back to owning nothing.
pub struct Borrow {
    mm: bool,
    fdt: bool,
    _creds: Option<CredsOverride>,
}

impl Borrow {
    /// Install `owner` on the running worker thread.
    ///
    /// # SAFETY: the caller must be a kernel worker thread with no address
    /// space and no descriptor table of its own, running in process context on
    /// its own CPU and holding no spinlock.
    /// # C: O(1)
    pub unsafe fn install(owner: &Owner) -> Self {
        if let Some(mm) = owner.mm.as_ref() {
            // SAFETY: forwarded fn-level contract — the running worker is a kernel thread with no address space, so this borrow displaces nothing.
            unsafe { sched::live::kthread_use_mm(mm); }
        }
        if let Some(fdt) = owner.fdt.as_ref() {
            if let Some(cur) = sched::live::current() {
                // SAFETY: forwarded fn-level contract — the running worker is the sole mutator of its own fd_table slot on this CPU.
                unsafe { cur.replace_fd_table(Some(Arc::clone(fdt))); }
            }
        }
        Self {
            mm: owner.mm.is_some(),
            fdt: owner.fdt.is_some(),
            _creds: owner.creds.as_ref().map(|c| CredsOverride::install(c)),
        }
    }
}

impl Drop for Borrow {
    /// # C: O(1)
    fn drop(&mut self) {
        if self.fdt {
            if let Some(cur) = sched::live::current() {
                // SAFETY: the running worker is the sole mutator of its own fd_table slot on this CPU; this releases exactly the table `install` put there.
                unsafe { cur.replace_fd_table(None); }
            }
        }
        if self.mm {
            // SAFETY: pairs with the `kthread_use_mm` this guard's `install` performed on this same thread.
            unsafe { sched::live::kthread_unuse_mm(); }
        }
    }
}
