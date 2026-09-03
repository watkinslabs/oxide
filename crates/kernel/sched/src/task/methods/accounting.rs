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
    /// Linux `add_rchar(current, ret)` + `inc_syscr(current)` after vfs_read. # C: O(1)
    pub fn account_read_result(&self, ret: i64) {
        self.debug_check_canary("account_read_result");
        if ret >= 0 {
            self.io_rchar.fetch_add(ret as u64, Ordering::Relaxed);
        }
        self.io_syscr.fetch_add(1, Ordering::Relaxed);
    }

    /// Linux `add_wchar(current, ret)` + `inc_syscw(current)` after vfs_write. # C: O(1)
    pub fn account_write_result(&self, ret: i64) {
        self.debug_check_canary("account_write_result");
        if ret >= 0 {
            self.io_wchar.fetch_add(ret as u64, Ordering::Relaxed);
        }
        self.io_syscw.fetch_add(1, Ordering::Relaxed);
    }

    /// Lift this task's vruntime to `floor` if it's currently below. Wake
    /// placement must never erase CPU debt accumulated before the sleep.
    /// `13§5` invariant 5.
    /// # C: O(1)
    pub fn lift_vruntime(&self, floor: u64) {
        self.debug_check_canary("lift_vruntime");
        let cur = self.sched.se.vruntime.load(Ordering::Acquire);
        if cur < floor { self.sched.se.vruntime.store(floor, Ordering::Release); }
    }
}
