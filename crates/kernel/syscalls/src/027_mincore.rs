// 027 mincore — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_mincore(addr, len, vec)` — slot 27. Per-page residency via MMU translate.
/// # C: O(len/4096)
pub fn sys_mincore(args: &SyscallArgs) -> i64 {
    use hal::{MmuOps, UserVirtAddr, Va};
    use syscall::errno::Errno;
    let (addr, len, vec) = (args.a0, args.a1, args.a2);
    if addr == 0 || (addr & 0xFFF) != 0 { return -(Errno::Einval.as_i32() as i64); }
    let pages = (len + 0xfff) / 0x1000;
    if vec == 0 || vec.checked_add(pages).map_or(true, |e| e >= hal::USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Einval.as_i32() as i64) };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return -(Errno::Einval.as_i32() as i64) };
    for i in 0..pages {
        let va = addr + i * 0x1000;
        let p = match UserVirtAddr::new(va) { Some(u) => u, None => return -(Errno::Enomem.as_i32() as i64) };
        if mm.find_vma(p).is_none() { return -(Errno::Enomem.as_i32() as i64); }
        let r: u8 = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::X86Mmu::translate(Va(va)).map_or(0, |_| 1) }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::ArmMmu::translate(Va(va)).map_or(0, |_| 1) }
        };
        // SAFETY: vec+i validated < USER_VA_END above; CPL=0 byte write through caller's AS.
        unsafe { core::ptr::write_volatile((vec + i) as *mut u8, r); }
    }
    0
}
