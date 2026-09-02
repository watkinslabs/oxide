//! Native NT thread construction, kept separate from Linux spawn paths.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::task::dup;
use crate::Task;
use vmm::AddressSpace;

use super::spawn::{arm_user_entry, new_user_task_unpublished, inherit, SpawnError};

/// Build an unpublished NT thread sharing the caller's process group/address space.
/// Publication remains with the caller so output-handle faults can discard it safely.
/// # SAFETY: caller is the running NT task; mm, entry, and stack belong to it.
/// # C: O(N_seccomp_filters + N_landlock_rules)
pub unsafe fn new_nt_thread_unpublished(
    tid: u32, entry_va: u64, user_sp: u64, parameter: u64, teb: u64, mm: Arc<AddressSpace>,
    group: Arc<crate::thread_group::ThreadGroup>,
) -> Result<Arc<Task>, SpawnError> {
    // SAFETY: caller guarantees allocator/HAL state and keeps the task unpublished.
    let mut task = unsafe { new_user_task_unpublished(tid, 0, 0, "nt-thread", mm)? };
    let child = dup::unique_mut(&mut task);
    child.join_thread_group(group);
    inherit::inherit_from_parent(child);
    if let Some(parent) = crate::live::current() {
        child.tgid.store(parent.tgid.load(Ordering::Acquire), Ordering::Release);
        child.security.vtgid.store(parent.security.vtgid.load(Ordering::Acquire), Ordering::Release);
        child.set_nt_personality(true);
        child.set_nt_peb(parent.nt_peb());
    }
    child.set_nt_teb(teb);
    child.set_nt_start_address(entry_va);
    // SAFETY: task remains unpublished and entry/stack belong to its mm.
    unsafe { arm_user_entry(child, entry_va, user_sp); }
    // SAFETY: synthetic user frame was just created on this unpublished kernel stack.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ctx = child.arch_ctx_ptr::<hal_x86_64::ContextX86_64>();
        let regs = ((*ctx).rsp + core::mem::size_of::<u64>() as u64) as *mut hal_x86_64::PtRegs;
        (*regs).rcx = parameter;
        (*ctx).gs_base = teb;
        #[cfg(feature = "debug-faultdiag")]
        {
            klog::write_raw(b"[WINDOWS-PE-THREAD-CONTEXT] tid=");
            klog::write_dec_u64(tid as u64);
            klog::write_raw(b" rip=");
            klog::write_hex_u64((*regs).rip);
            klog::write_raw(b" rsp=");
            klog::write_hex_u64((*regs).rsp);
            klog::write_raw(b" rcx=");
            klog::write_hex_u64((*regs).rcx);
            klog::write_raw(b" gs=");
            klog::write_hex_u64((*ctx).gs_base);
            klog::write_raw(b"\n");
        }
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: child is unpublished and its context is exclusively initialized here.
    unsafe {
        let ctx = child.arch_ctx_ptr::<hal_aarch64::ContextAArch64>();
        *((*ctx).sp as *mut u64) = parameter;
        (*ctx).tpidr = teb;
    }
    Ok(task)
}
