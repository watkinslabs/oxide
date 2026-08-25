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

#[cfg(feature = "debug-smp")]
pub(crate) const TASK_CANARY_HEAD: u64 = 0x5441_534b_4845_4144;
#[cfg(feature = "debug-smp")]
pub(crate) const TASK_CANARY_TAIL: u64 = 0x5441_534b_5441_494c;
#[cfg(any(feature = "debug-smp", feature = "debug-stack-guard"))]
pub(crate) const TASK_STACK_GUARD: u8 = 0xa5;
#[cfg(any(feature = "debug-smp", feature = "debug-stack-guard"))]
pub(crate) const TASK_STACK_GUARD_BYTES: usize = 32;
#[cfg(any(feature = "debug-smp", feature = "debug-stack-guard"))]
pub(crate) const TASK_STACK_WATERMARK_OFF: usize = 16 * 1024;

#[cfg(feature = "debug-smp")]
#[inline]
pub(crate) fn task_canary_head(tid: u32) -> u64 {
    TASK_CANARY_HEAD ^ ((tid as u64) << 32) ^ tid as u64
}

#[cfg(feature = "debug-smp")]
#[inline]
pub(crate) fn task_canary_tail(tid: u32) -> u64 {
    TASK_CANARY_TAIL ^ ((tid as u64) << 17) ^ ((tid as u64) << 1)
}

/// Snapshot the architectural stack pointer without creating another Rust
/// frame.  This is diagnostic-only: when a stack guard is damaged, it tells
/// us whether the CPU is actually executing in that allocation or whether an
/// unrelated write overlapped it.
#[cfg(all(any(feature = "debug-smp", feature = "debug-stack-guard"), target_arch = "aarch64"))]
#[inline]
pub(crate) fn debug_stack_pointer() -> usize {
    let sp: usize;
    // SAFETY: reads the architectural SP register only; no memory or flags
    // are changed.  AArch64 permits `mov <gpr>, sp` at EL1.
    unsafe { core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags)); }
    sp
}

#[cfg(all(any(feature = "debug-smp", feature = "debug-stack-guard"), target_arch = "aarch64"))]
#[inline]
pub(crate) fn debug_frame_pointer() -> usize {
    let fp: usize;
    // SAFETY: reads x29 only; see `debug_stack_pointer`.
    unsafe { core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack, preserves_flags)); }
    fp
}

#[cfg(all(any(feature = "debug-smp", feature = "debug-stack-guard"), not(target_arch = "aarch64")))]
#[inline]
pub(crate) fn debug_frame_pointer() -> usize { 0 }

#[cfg(all(any(feature = "debug-smp", feature = "debug-stack-guard"), not(target_arch = "aarch64")))]
#[inline]
pub(crate) fn debug_stack_pointer() -> usize { 0 }


impl Task {
    /// Debug-smp Task lifetime sentinel. Trips when a stale `Task*` is used after
    /// its allocation was freed/reused, before the later victim object faults.
    /// The task-identity canary (`dbg_canary_head`/`tail`) needs `debug-smp`
    /// itself (owns the fields); the stack-guard-byte check below only needs
    /// `self.stack`, so `debug-stack-guard` alone (no `sync/debug-smp` spin-
    /// probe overhead) can run it standalone — see `state.md`: `debug-smp`'s
    /// overhead was found to destabilize an unrelated early-boot ext4 mount
    /// path, blocking this check from ever running this session.
    /// # C: O(1)
    #[cfg(any(feature = "debug-smp", feature = "debug-stack-guard"))]
    #[track_caller]
    pub fn debug_check_canary(&self, site: &'static str) {
        #[cfg(feature = "debug-smp")]
        {
            let eh = task_canary_head(self.tid);
            let et = task_canary_tail(self.tid);
            let gh = self.dbg_canary_head.load(Ordering::Acquire);
            let gt = self.security.dbg_canary_tail.load(Ordering::Acquire);
            if gh != eh || gt != et {
                klog::write_raw(b"[TASK-CANARY site=");
                klog::write_raw(site.as_bytes());
                klog::write_raw(b" ptr=");
                klog::write_hex_u64(self as *const Task as u64);
                klog::write_raw(b" tid=");
                klog::write_dec_u64(self.tid as u64);
                klog::write_raw(b" tid_addr=");
                klog::write_hex_u64((&self.tid as *const u32) as u64);
                klog::write_raw(b" ctx_addr=");
                klog::write_hex_u64(self.arch_ctx.get() as u64);
                klog::write_raw(b" head=");
                klog::write_hex_u64(gh);
                klog::write_raw(b" tail=");
                klog::write_hex_u64(gt);
                klog::write_raw(b"]\n");
            }
            hal::kassert!(gh == eh && gt == et, "Task canary corrupted");
        }
        if let Some(gstack) = self.stack.lock().as_ref() {
            let stack = gstack.as_slice();
            let guard_len = core::cmp::min(TASK_STACK_GUARD_BYTES, stack.len());
            let watermark_live = stack.len() >= TASK_STACK_WATERMARK_OFF + guard_len
                && stack[TASK_STACK_WATERMARK_OFF..TASK_STACK_WATERMARK_OFF + guard_len]
                    .iter().any(|&b| b != TASK_STACK_GUARD);
            let mut i = 0usize;
            while i < guard_len && stack[i] == TASK_STACK_GUARD {
                i += 1;
            }
            if i != guard_len {
                let sp = debug_stack_pointer();
                let fp = debug_frame_pointer();
                let caller = core::panic::Location::caller();
                let stack_lo = stack.as_ptr() as usize;
                let stack_hi = stack_lo.saturating_add(stack.len());
                let sp_in_stack = sp >= stack_lo && sp < stack_hi;
                klog::write_raw(b"[TASK-STACK-GUARD site=");
                klog::write_raw(site.as_bytes());
                klog::write_raw(b" task=");
                klog::write_hex_u64(self as *const Task as u64);
                klog::write_raw(b" tid=");
                klog::write_dec_u64(self.tid as u64);
                klog::write_raw(b" stack=");
                klog::write_hex_u64(stack_lo as u64);
                klog::write_raw(b" stack_hi=");
                klog::write_hex_u64(stack_hi as u64);
                klog::write_raw(b" sp=");
                klog::write_hex_u64(sp as u64);
                klog::write_raw(b" fp=");
                klog::write_hex_u64(fp as u64);
                klog::write_raw(b" sp_in_stack=");
                klog::write_dec_u64(sp_in_stack as u64);
                klog::write_raw(b" caller_line=");
                klog::write_dec_u64(caller.line() as u64);
                klog::write_raw(b" offset=");
                klog::write_dec_u64(i as u64);
                klog::write_raw(b" crossed_16k=");
                klog::write_dec_u64(watermark_live as u64);
                klog::write_raw(b"]\n");
                panic!("Task kernel stack underflow");
            }
        }
    }

    /// # C: O(1)
    #[cfg(not(any(feature = "debug-smp", feature = "debug-stack-guard")))]
    #[inline]
    pub fn debug_check_canary(&self, _site: &'static str) {}

    /// Validate the boxed FP/SIMD save-area identity before raw asm or ptrace
    /// access. Reading only the Box representation is deliberate: it lets the
    /// diagnostic reject a corrupt pointer before Rust or the architecture code
    /// dereferences it.
    /// # C: O(1)
    #[cfg(feature = "debug-task-fpu-provenance")]
    pub fn debug_check_fpu_state(&self, site: &'static str) {
        let expected = self.security.dbg_fpu_state_expected.load(Ordering::Acquire);
        // SAFETY: this reads the pointer-sized Box representation from the
        // task-owned UnsafeCell without dereferencing the candidate address;
        // scheduler/ptrace serialization prevents a concurrent field mutation.
        let actual = unsafe { core::ptr::read(self.security.fpu_state.get().cast::<usize>()) };
        let align = ArchFpuBuf::debug_alignment();
        let valid = actual == expected && actual != 0 && actual & (align - 1) == 0;
        if !valid {
            klog::write_raw(b"[TASK-FPU-PROVENANCE site=");
            klog::write_raw(site.as_bytes());
            klog::write_raw(b" task=");
            klog::write_hex_u64(self as *const Task as u64);
            klog::write_raw(b" tid=");
            klog::write_dec_u64(self.tid as u64);
            klog::write_raw(b" expected=");
            klog::write_hex_u64(expected as u64);
            klog::write_raw(b" actual=");
            klog::write_hex_u64(actual as u64);
            klog::write_raw(b" last_syscall=");
            klog::write_dec_u64(self.last_syscall_nr.load(Ordering::Acquire) as u64);
            klog::write_raw(b"]\n");
        }
        hal::kassert!(valid, "Task FPU state pointer corrupted");
    }

    /// # C: O(1)
    #[cfg(not(feature = "debug-task-fpu-provenance"))]
    #[inline]
    pub fn debug_check_fpu_state(&self, _site: &'static str) {}
}
