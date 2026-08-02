// 024 sched_yield — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(any(target_os = "oxide-kernel", test))]

use syscall::SyscallArgs;

#[cfg(target_os = "oxide-kernel")]
fn do_sched_yield() {
    if sched::live::global().is_some() {
        // SAFETY: process ctx; runqueue installed; preempt-off through syscall handler; Linux sched_yield marker is consumed in schedule before requeue.
        unsafe { sched::live::sched_yield(); }
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn do_sched_yield() {}

/// `sys_sched_yield()` — slot 24. scheduler class yield + 0.
/// # C: O(log N)
pub fn sys_sched_yield(_args: &SyscallArgs) -> i64 {
    // DIAG (debug-syscall): a process spinning on sched_yield (the boot wedge)
    // never makes progress. Log the caller's user RIP every Nth yield so the
    // spin loop can be symbolized (which lock/condition it busy-waits on).
    #[cfg(all(target_os = "oxide-kernel", feature = "debug-syscall"))]
    {
        use core::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let c = N.fetch_add(1, Ordering::Relaxed);
        if c % 20000 == 0 {
            // User PC + user SP at trap entry, arch-neutral: x86 saves them in
            // the [rip,_,rsp] user frame; aarch64 in the SVC frame (elr_el1 =
            // user PC, sp_el0 = user SP). Same YIELD-SPIN symbolization below.
            // SAFETY: current_pt_regs() is this task's live syscall entry frame; rip is the trapped user PC.
            #[cfg(target_arch = "x86_64")]
            let rip = { let f = hal_x86_64::current_pt_regs(); if f.is_null() { 0 } else { unsafe { (*f).rip } } };
            // SAFETY: current_svc_frame() is this CPU's live SVC frame; elr_el1 is the trapped user PC.
            #[cfg(target_arch = "aarch64")]
            let rip = { let f = hal_aarch64::current_svc_frame(); if f.is_null() { 0 } else { unsafe { (*f).elr_el1 } } };
            let cur = sched::live::current();
            let tid = cur.as_ref().map(|t| t.tid).unwrap_or(0);
            klog::write_raw(b"[mnt] YIELD-SPIN rip="); klog::write_hex_u64(rip);
            klog::write_raw(b" tid=");                 klog::write_dec_u64(tid as u64);
            // Symbolize the spinning RIP to (library ino, file offset) so the
            // exact glibc function can be disassembled.
            // __sched_yield is a leaf (syscall;ret) so the CALLER's return
            // address is at [user_rsp]. Symbolize BOTH the direct caller and
            // its caller (2 stack slots) to (library ino, file offset).
            // SAFETY: current_pt_regs() is this task's live syscall entry frame; rsp is the trapped user SP.
            #[cfg(target_arch = "x86_64")]
            let ursp = unsafe { hal_x86_64::current_user_sp(hal_x86_64::current_pt_regs()) };
            // SAFETY: current_svc_frame() is this CPU's live SVC frame; sp_el0 is the trapped user SP.
            #[cfg(target_arch = "aarch64")]
            let ursp = { let f = hal_aarch64::current_svc_frame(); if f.is_null() { 0 } else { unsafe { (*f).sp_el0 } } };
            if let Some(c) = cur.as_ref() {
                // SAFETY: running task on this CPU; single-mutator mm slot.
                if let Some(mm) = unsafe { c.mm_ref() } {
                    let symbolize = |label: &'static [u8], addr: u64| {
                        if let Some(uva) = hal::UserVirtAddr::new(addr) {
                            if let Some(vma) = mm.find_vma(uva) {
                                if let vmm::VmaBacking::File { backing, off } = &vma.backing {
                                    let foff = off.wrapping_add(addr - vma.start.as_u64());
                                    klog::write_raw(label);
                                    klog::write_raw(b"ino="); klog::write_hex_u64(backing.ino());
                                    klog::write_raw(b"/foff="); klog::write_hex_u64(foff);
                                }
                            }
                        }
                    };
                    // Scan the top few stack quads for the first two that fall
                    // in a File VMA's exec range (return addresses).
                    let mut found = 0u32;
                    let mut i = 0u64;
                    while i < 16 && found < 3 {
                        // A user stack slot may be unmapped or misaligned; the
                        // uaccess path faults to EFAULT instead of taking a
                        // kernel #PF on a raw dereference.
                        let a = { let mut b = [0u8; 8];
                            if uaccess::copy_from_user(&mut b, ursp + i * 8).is_err() { break; }
                            u64::from_ne_bytes(b) };
                        if let Some(uva) = hal::UserVirtAddr::new(a) {
                            if let Some(vma) = mm.find_vma(uva) {
                                if vma.prot.contains(vmm::VmaProt::EXEC)
                                    && matches!(vma.backing, vmm::VmaBacking::File { .. }) {
                                    symbolize(b" caller", a);
                                    found += 1;
                                    // libcap spinlock return is at file-offset
                                    // 0xdad; the lock byte is at 0xb044. Read it
                                    // + the frame refcount (>1 = COW-shared =
                                    // fork-lock-inherit bug; ==1 = private, so a
                                    // lost unlock write).
                                    if let vmm::VmaBacking::File { off, .. } = &vma.backing {
                                        let cfoff = off.wrapping_add(a - vma.start.as_u64());
                                        if cfoff == 0xdad {
                                            let lock_va = a.wrapping_add(0xb044 - 0xdad);
                                            let byte = { let mut b = [0u8; 1];
                                                if uaccess::copy_from_user(&mut b, lock_va).is_err() { b[0] = 0; }
                                                b[0] };
                                            klog::write_raw(b" LOCK@"); klog::write_hex_u64(lock_va);
                                            klog::write_raw(b"=");      klog::write_hex_u64(byte as u64);
                                            #[cfg(target_arch = "x86_64")]
                                            if let Some((pa, _)) =
                                                <hal_x86_64::mmu_ops::X86Mmu as hal::MmuOps>::translate(hal::Va(lock_va & !0xfff)) {
                                                klog::write_raw(b" rc="); klog::write_dec_u64(pmm::setup::frame_refcount(pa.0 & !0xfff) as u64);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        i += 1;
                    }
                }
            }
            klog::write_raw(b"\n");
        }
    }
    do_sched_yield();
    0
}
