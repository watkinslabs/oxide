// 010 mprotect — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_mprotect(addr, len, prot)` — slot 10. Updates the VMA's
/// `prot` field and walks the live page tables to flip W/X bits +
/// flush the TLB per `11§6` via `pmm::user_as::mprotect_pages`.
/// # C: O(len / PAGE_SIZE)
pub fn sys_mprotect(args: &SyscallArgs) -> i64 {
    use vmm::VmaProt;
    use hal::UserVirtAddr;
    use syscall::errno::Errno;
    let addr = args.a0;
    let len  = args.a1 as usize;
    let prot = args.a2 as u32;
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return 0 };
    let mut vp = VmaProt::empty();
    if (prot & 0x1) != 0 { vp |= VmaProt::READ;  }
    if (prot & 0x2) != 0 { vp |= VmaProt::WRITE; }
    if (prot & 0x4) != 0 { vp |= VmaProt::EXEC;  }
    let ua = match UserVirtAddr::new(addr) {
        Some(u) => u, None => return -(Errno::Einval.as_i32() as i64),
    };
    // mseal(2): a sealed VMA in the range rejects mprotect with EPERM.
    if mm.range_sealed(ua, len) { return -(Errno::Eperm.as_i32() as i64); }
    match mm.mprotect(ua, len, vp) {
        Ok(()) => {
            // SAFETY: caller is the running task; mm matches active AS; per-AS UP + preempt-off serialises with fault path; mprotect_pages walks PT + flushes TLB so hardware enforces the new permissions.
            unsafe { pmm::user_as::mprotect_pages(mm.root_pa(), addr, len, vp); }
            0
        }
        Err(_) => -(Errno::Einval.as_i32() as i64),
    }
}
