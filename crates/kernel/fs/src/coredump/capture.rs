// Reading the dying process into the builder's inputs.
//
// Everything the assembler needs and nothing it decides: the crashing thread's
// register and floating-point blocks, the killing signal's descriptor, the
// process identity, the auxiliary vector, and the mapping list the selection
// ladder produced. The ladder itself, the plan it yields and the image layout
// all live in modules with no target gate; this file only fetches.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::elf::{
    build_core_image, CoreArch, CoreIdentity, CoreImageInput, CoreSegFile, CoreSegment, CoreState,
    CoreThread, CoreTimeval, CoreTimes,
};
use super::gregset;
use super::pattern::CoreContext;
use super::plan::{plan_mappings, PlannedSegment};
use crate::sig_dispatch::UserRegs;

/// Bytes of the `siginfo_t` a `NT_SIGINFO` note carries.
const SIGINFO_BYTES: usize = 128;

/// Microseconds per second, for the CPU-time fields `elf_prstatus` carries as
/// `timeval`s.
const US_PER_SEC: u64 = 1_000_000;

/// Nanoseconds per microsecond.
const NS_PER_US: u64 = 1_000;

/// Page granularity the memory half is planned and read in.
const PAGE: u64 = hal::PAGE_SIZE_BYTES;

fn timeval_of_ns(ns: u64) -> CoreTimeval {
    CoreTimeval { sec: (ns / (US_PER_SEC * NS_PER_US)) as i64, usec: (ns / NS_PER_US % US_PER_SEC) as i64 }
}

/// The crashing thread's register block, taken from the entry frame it is
/// about to be torn down from — the one place this port keeps user state.
/// # SAFETY: `regs` is the calling thread's live entry frame.
unsafe fn regs_block(cur: &sched::Task, regs: *const UserRegs) -> Vec<u8> {
    let arch = CoreArch::native();
    if regs.is_null() { return alloc::vec![0u8; arch.gregset_bytes()] }
    #[cfg(target_arch = "x86_64")]
    {
        // The two segment bases are not in the frame: they live in the saved
        // context the switch reloads, which is the same pair a tracer reads.
        // SAFETY: `cur` is the running task, so no CPU is switching its context; `arch_ctx_ptr` returns its own context buffer, whose fs_base/gs_base fields the ctxsw keeps in step with the machine registers.
        let (fs_base, gs_base) = unsafe {
            let p = cur.arch_ctx_ptr::<hal_x86_64::ContextX86_64>();
            ((*p).fs_base, (*p).gs_base)
        };
        // SAFETY: caller's contract — `regs` is this thread's live entry frame, singly owned for the read.
        unsafe { gregset::current_block(regs, &gregset::X86SegBases { fs_base, gs_base }) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = cur;
        // SAFETY: caller's contract — `regs` is this thread's live entry frame, singly owned for the read.
        unsafe { gregset::current_block(regs) }
    }
}

/// The crashing thread's floating-point block. The live registers are flushed
/// into the task's own save area first: the thread is still running, so the
/// area holds whatever the last context switch left there.
fn fpregs_block(cur: &sched::Task) -> Vec<u8> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: `cur` is the running task and this CPU owns its FPU save area under the single-mutator rule; `fpu_save` writes exactly the area `ArchFpuBuf` allocated, 64-byte aligned.
        unsafe {
            let p = (*cur.fpu_state.get()).as_mut_ptr();
            hal_x86_64::fpu_save(p as *mut hal_x86_64::FpuStateX86_64);
            // The note carries the legacy save area, which is the first bytes
            // of the region whatever wider format the machine saves in.
            core::slice::from_raw_parts(p as *const u8, CoreArch::X86_64.fpregset_bytes()).to_vec()
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: `cur` is the running task and this CPU owns its FPU save area under the single-mutator rule; `fpu_save` writes exactly the area `ArchFpuBuf` allocated.
        unsafe {
            let p = (*cur.fpu_state.get()).as_mut_ptr();
            hal_aarch64::fpu_save(p as *mut hal_aarch64::FpuStateAArch64);
            let st = &*(p as *const hal_aarch64::FpuStateAArch64);
            gregset::aarch64_fpregs_block(&st.q, st.fpsr, st.fpcr)
        }
    }
}

/// Mapping list and a reader for their contents, or nothing at all when the
/// process has already given up its address space.
fn plan_for(cur: &sched::Task) -> (Vec<PlannedSegment>, u64, Vec<u8>) {
    // SAFETY: `cur` is the running task, so its mm slot cannot be replaced under us; the reference is used only for the duration of this snapshot.
    let Some(mm) = (unsafe { cur.mm_ref() }) else { return (Vec::new(), 0, Vec::new()) };
    let root_pa = mm.root_pa();
    let vmas = mm.snapshot_vmas();
    let mut head = |va: u64, buf: &mut [u8]| -> usize {
        // SAFETY: `root_pa` is the running task's own page-table root, held live by its mm; the walk only reads present leaves through the HHDM.
        unsafe { pmm::user_as::read_foreign_user(root_pa, va, buf) }
    };
    let (vdso_start, vdso_end) = mm.vdso_range();
    let segs = plan_mappings(&vmas, vdso_start, vdso_end, mm.coredump_filter(), PAGE, &mut head);
    (segs, root_pa, mm.auxv().unwrap_or_default())
}

/// Assemble the image for the dying process.
/// # SAFETY: `regs` is the calling thread's live entry frame, or null.
/// # C: O(dump size)
pub unsafe fn build_image(
    cx: &CoreContext, regs: *const UserRegs, payload: Option<hal::SigPayload>,
) -> Vec<u8> {
    let Some(cur) = sched::live::current() else { return Vec::new() };
    let arch = CoreArch::native();
    // SAFETY: caller's contract — `regs` is this thread's live entry frame.
    let gregs = unsafe { regs_block(&cur, regs) };
    let fpregs = fpregs_block(&cur);
    let (planned, root_pa, auxv) = plan_for(&cur);
    let segs: Vec<CoreSegment<'_>> = planned.iter().map(|p| CoreSegment {
        start: p.start, end: p.end, prot: p.prot, dump_size: p.dump_size,
        file: p.file.as_ref().map(|f| CoreSegFile { path: &f.path, pgoff_pages: f.pgoff_pages }),
    }).collect();

    let mut si = [0u8; SIGINFO_BYTES];
    hal::write_siginfo(&mut si, cx.signo as u32, payload);
    let cmdline = cur.cmdline().unwrap_or_default();
    let psargs = if cmdline.is_empty() { cx.comm.clone() } else { cmdline.into_bytes() };
    let runtime = cur.sum_exec_runtime_ns.load(Ordering::Acquire);

    let threads = [CoreThread { tid: cx.vtid as i32, regs: &gregs, fpregs: Some(&fpregs), xstate: None }];
    let input = CoreImageInput {
        arch,
        identity: CoreIdentity {
            pid: cx.vpid as i32,
            ppid: sched::live::registry::parent_vpid(cur.tid) as i32,
            pgrp: cur.pgid() as i32,
            sid: cur.sid() as i32,
            uid: cx.uid, gid: cx.gid,
            signo: cx.signo,
            sigpend: sched::live::sigpend::all_pending(&cur),
            sighold: cur.sigmask.load(Ordering::Acquire),
            state: CoreState::Running,
            nice: cur.nice.load(Ordering::Acquire),
            flag: 0,
            comm: &cx.comm, psargs: &psargs,
            times: CoreTimes { utime: timeval_of_ns(runtime), ..CoreTimes::default() },
        },
        threads: &threads,
        segments: &segs,
        auxv: &auxv,
        siginfo: Some(&si),
    };
    let mut mem = |va: u64, buf: &mut [u8]| -> usize {
        if root_pa == 0 { return 0 }
        // SAFETY: `root_pa` is the running task's own page-table root, held live by its mm; the walk only reads present leaves through the HHDM, and a page it cannot resolve becomes a hole.
        unsafe { pmm::user_as::read_foreign_user(root_pa, va, buf) }
    };
    match build_core_image(&input, &mut mem) {
        Ok(v) => v,
        // A dump has no caller to report to, so an image the assembler refused
        // would otherwise be indistinguishable from one it never built.
        Err(e) => { image_refused(e, segs.len(), gregs.len()); Vec::new() }
    }
}

/// DIAG (`debug-boot`): the assembler refused the inputs.
#[cfg(feature = "debug-boot")]
fn image_refused(e: super::elf::CoreImageError, segs: usize, regs: usize) {
    klog::write_raw(b"[COREDUMP] image-refused err=");
    klog::write_dec_u64(e as u64);
    klog::write_raw(b" segs="); klog::write_dec_u64(segs as u64);
    klog::write_raw(b" regs="); klog::write_dec_u64(regs as u64);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-boot"))]
fn image_refused(_e: super::elf::CoreImageError, _segs: usize, _regs: usize) {}
