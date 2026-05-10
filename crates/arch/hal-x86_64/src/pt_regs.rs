// x86_64 user-state register frame per `15§1.1` + `20§*` syscall
// entry path. The trampoline asm (lands in a follow-up once KPTI +
// per-CPU kernel stack do) saves user GPRs into a `PtRegsX86_64`
// frame on the kernel stack, then calls `dispatch_from_pt_regs`.
//
// SysV-AMD64 syscall calling convention (`15§1.1`):
//   nr     = rax
//   args   = rdi, rsi, rdx, r10, r8, r9   (r10 NOT rcx — syscall clobbers rcx)
//   ret    = rax (`-errno` on error per `15§1.3`)
//   saved  = rcx (user RIP), r11 (user RFLAGS) — clobbered by `syscall` insn
//
// Layout is asm-coupled. The trampoline references `[rsp + 0xNN]`
// from the saved frame; reordering breaks the boundary. Tests pin
// every offset.

use syscall::{dispatch, SyscallArgs};

/// Saved user-state on syscall / IRQ entry. The trampoline pushes
/// caller-saved + callee-saved GPRs in this exact order; the
/// kernel sees them as a contiguous `PtRegsX86_64`.
///
/// Order chosen for cheap `pushq` sequence in the trampoline; the
/// frame is overwritten with restored values before `sysretq`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PtRegsX86_64 {
    // 0x00 — caller-saved GPRs (saved by trampoline).
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub r11: u64, pub r10: u64, pub  r9: u64, pub  r8: u64,
    pub rbp: u64, pub rbx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64, pub rsi: u64, pub rdi: u64,
    // 0x78 — pseudo-frame: user RIP / CS / RFLAGS / SP / SS as
    // delivered by `syscall` (RIP in rcx, RFLAGS in r11; for IRQ entry
    // these come from the IRET frame). Stored explicitly so the
    // dispatch path doesn't have to reach back into the asm context.
    pub user_rip:    u64,
    pub user_rflags: u64,
    pub user_rsp:    u64,
    pub user_cs:     u64,
    pub user_ss:     u64,
}

impl PtRegsX86_64 {
    /// Extract the 6 syscall arg registers per `15§1.1`.
    /// # C: O(1)
    pub fn to_syscall_args(&self) -> SyscallArgs {
        SyscallArgs {
            a0: self.rdi,
            a1: self.rsi,
            a2: self.rdx,
            a3: self.r10,  // NOT rcx — syscall clobbers rcx
            a4: self.r8,
            a5: self.r9,
        }
    }

    /// # C: O(1)
    pub fn syscall_nr(&self) -> u32 { self.rax as u32 }

    /// Write the syscall return value back into the place userspace
    /// reads from (rax) per `15§1.3`.
    /// # C: O(1)
    pub fn set_return(&mut self, rv: i64) {
        self.rax = rv as u64;
    }
}

/// Bridge from the trampoline's `PtRegsX86_64` frame to the
/// architecture-neutral `syscall::dispatch`. The asm landing pad
/// (`oxide_syscall_entry`) calls this with `regs = current
/// per-CPU kernel-stack PtRegs frame`.
///
/// # SAFETY: `regs` points to a fully-populated `PtRegsX86_64` on
/// the current kernel stack; the kernel owns the frame; userspace
/// can't observe it until `sysretq` is reached.
/// # C: O(1) + dispatch fn cost
#[no_mangle]
pub unsafe extern "C" fn oxide_dispatch_from_pt_regs_x86_64(regs: *mut PtRegsX86_64) {
    // SAFETY: regs is a kernel-stack pointer to a populated frame
    // per the function contract above; the trampoline guarantees
    // it lives across this call. We need both a read (args+nr) and
    // a write-back (rax) which is why we take `*mut`.
    let r = unsafe { &mut *regs };
    let nr   = r.syscall_nr();
    let args = r.to_syscall_args();
    let rv   = dispatch(nr, &args);
    r.set_return(rv);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_offsets_pin_the_asm_boundary() {
        // Lock these — the trampoline asm uses literal `[rsp + 0xNN]`
        // offsets to save/restore. Any reordering breaks the boundary.
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, r15), 0x00);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, r14), 0x08);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, r13), 0x10);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, r12), 0x18);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, r11), 0x20);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, r10), 0x28);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64,  r9), 0x30);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64,  r8), 0x38);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, rbp), 0x40);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, rbx), 0x48);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, rax), 0x50);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, rcx), 0x58);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, rdx), 0x60);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, rsi), 0x68);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, rdi), 0x70);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, user_rip),    0x78);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, user_rflags), 0x80);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, user_rsp),    0x88);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, user_cs),     0x90);
        assert_eq!(core::mem::offset_of!(PtRegsX86_64, user_ss),     0x98);
        assert_eq!(core::mem::size_of::<PtRegsX86_64>(),             0xa0);
    }

    #[test]
    fn args_extracted_per_sysv_amd64_convention() {
        // `15§1.1`: nr=rax; args=rdi,rsi,rdx,r10,r8,r9. Note r10 not rcx.
        let regs = PtRegsX86_64 {
            rax: 9, // sys_mmap
            rdi: 0x1000, rsi: 0x4000, rdx: 0x7,
            r10: 0x32, r8: 0x0, r9: 0x0,
            ..Default::default()
        };
        assert_eq!(regs.syscall_nr(), 9);
        let args = regs.to_syscall_args();
        assert_eq!(args.a0, 0x1000);
        assert_eq!(args.a1, 0x4000);
        assert_eq!(args.a2, 0x7);
        assert_eq!(args.a3, 0x32, "a3 must come from r10, not rcx");
        assert_eq!(args.a4, 0x0);
        assert_eq!(args.a5, 0x0);
    }

    #[test]
    fn dispatch_writes_back_to_rax() {
        let mut regs = PtRegsX86_64::default();
        regs.rax = 7777; // unimplemented syscall ⇒ ENOSYS
        // SAFETY: hosted test; `regs` is a stack-local PtRegs that
        // lives across this call; `dispatch_from_pt_regs` reads
        // nr+args and writes rax — exactly its documented contract.
        unsafe {
            oxide_dispatch_from_pt_regs_x86_64(&mut regs as *mut _);
        }
        // ENOSYS = 38; encoded as `-(38i32 as i64) as u64` per `15§1.3`.
        let expected = -38i64 as u64;
        assert_eq!(regs.rax, expected, "rax must hold -errno on ENOSYS");
    }
}
