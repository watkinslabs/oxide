//! Bounded saved-task kernel-stack walking for procfs diagnostics.
//!
//! Linux's `proc_pid_stack` walks a task's saved kernel stack while holding the
//! task-stack lifetime reference.  This port has frame pointers enabled on the
//! supported kernel targets, so the same operation can be performed without
//! dereferencing arbitrary addresses: the saved context supplies the first
//! frame and the task-owned guarded stack supplies the only permitted range.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::Task;

const MAX_FRAMES: usize = 64;
const WORD: u64 = core::mem::size_of::<u64>() as u64;

/// Return saved return addresses for an off-CPU task.  A running or queued task
/// is intentionally reported as empty: its live stack is being mutated by the
/// scheduler and cannot be observed through this off-CPU snapshot safely.
/// # C: O(MAX_FRAMES)
pub fn saved(task: &Task) -> Vec<u64> {
    if task.on_cpu.load(Ordering::Acquire) || task.on_rq.load(Ordering::Acquire) {
        return Vec::new();
    }
    let stack = task.stack.lock();
    let Some(stack) = stack.as_ref() else { return Vec::new() };
    let lo = stack.base() as u64;
    let hi = lo.saturating_add(stack.len() as u64);
    if hi <= lo { return Vec::new(); }

    #[cfg(target_arch = "x86_64")]
    let (sp, fp, first_ip) = {
        let ctx = unsafe { &*task.arch_ctx_ptr::<hal_x86_64::ContextX86_64>() };
        (ctx.rsp, ctx.rbp, 0)
    };
    #[cfg(target_arch = "aarch64")]
    let (sp, fp, first_ip) = {
        let ctx = unsafe { &*task.arch_ctx_ptr::<hal_aarch64::ContextAArch64>() };
        (ctx.sp, ctx.x29, ctx.lr)
    };

    let mut out = Vec::with_capacity(MAX_FRAMES);
    if first_ip != 0 { out.push(first_ip); }
    walk_frames(lo, hi, sp, fp, &mut out);
    out
}

/// Walk an ABI frame-pointer chain after validating every frame and word read.
/// `sp` is used to reject a saved frame pointer below the active stack.
/// # C: O(MAX_FRAMES)
fn walk_frames(lo: u64, hi: u64, sp: u64, mut fp: u64, out: &mut Vec<u64>) {
    if fp == 0 { return; }
    if fp < lo.max(sp) || fp > hi.saturating_sub(2 * WORD) || fp & (WORD - 1) != 0 { return; }
    for _ in 0..MAX_FRAMES.saturating_sub(out.len()) {
        if fp < lo.max(sp) || fp > hi.saturating_sub(2 * WORD) || fp & (WORD - 1) != 0 { break; }
        // SAFETY: both words lie in the live, task-owned guarded stack range
        // checked above; the stack lock pins its backing allocation.
        let (next, ip) = unsafe {
            (core::ptr::read(fp as *const u64), core::ptr::read((fp + WORD) as *const u64))
        };
        if ip != 0 { out.push(ip); }
        if next <= fp || next == 0 { break; }
        fp = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_frames_outside_stack_or_below_saved_sp() {
        let mut out = Vec::new();
        walk_frames(0x1000, 0x1100, 0x1080, 0x1078, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn walks_only_a_monotonic_bounded_chain() {
        let mut words = [0u64; 8];
        let base = words.as_mut_ptr() as u64;
        words[0] = base + 16;
        words[1] = 0xaaaa;
        words[2] = 0;
        core::hint::black_box(&mut words[3]);
        words[3] = 0xbbbb;
        let mut out = Vec::new();
        walk_frames(base, base + 64, base, base, &mut out);
        assert_eq!(out, [0xaaaa, 0xbbbb]);
    }
}
