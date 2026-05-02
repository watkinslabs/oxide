// aarch64 user-state register frame per `15§1.2` + `21§*` syscall
// entry path. Trampoline (lands in a follow-up PR alongside the
// per-CPU kstack + PT root swap) saves user GPRs into a
// `PtRegsAArch64` frame on the kernel stack, then calls
// `oxide_dispatch_from_pt_regs_aarch64`.
//
// AAPCS64 syscall calling convention (`15§1.2`):
//   nr     = x8
//   args   = x0..x5
//   ret    = x0
//
// Layout is asm-coupled. Tests pin every offset.

use syscall::{dispatch, SyscallArgs};

/// Saved user-state on `svc` / IRQ entry. x0..x30 (31 GPRs) +
/// SP_EL0 + ELR_EL1 (user PC) + SPSR_EL1 (user pstate). 34 slots
/// × 8 bytes = 272 B.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PtRegsAArch64 {
    pub  x0: u64, pub  x1: u64, pub  x2: u64, pub  x3: u64,
    pub  x4: u64, pub  x5: u64, pub  x6: u64, pub  x7: u64,
    pub  x8: u64, pub  x9: u64, pub x10: u64, pub x11: u64,
    pub x12: u64, pub x13: u64, pub x14: u64, pub x15: u64,
    pub x16: u64, pub x17: u64, pub x18: u64, pub x19: u64,
    pub x20: u64, pub x21: u64, pub x22: u64, pub x23: u64,
    pub x24: u64, pub x25: u64, pub x26: u64, pub x27: u64,
    pub x28: u64, pub x29: u64, pub  lr: u64,             // x30
    pub sp_el0:   u64,
    pub elr_el1:  u64, // user PC at trap entry
    pub spsr_el1: u64, // user pstate
}

impl PtRegsAArch64 {
    /// Extract syscall args per `15§1.2`.
    /// # C: O(1)
    pub fn to_syscall_args(&self) -> SyscallArgs {
        SyscallArgs {
            a0: self.x0,
            a1: self.x1,
            a2: self.x2,
            a3: self.x3,
            a4: self.x4,
            a5: self.x5,
        }
    }

    /// # C: O(1)
    pub fn syscall_nr(&self) -> u32 { self.x8 as u32 }

    /// # C: O(1)
    pub fn set_return(&mut self, rv: i64) {
        self.x0 = rv as u64;
    }
}

/// Bridge from the trampoline's `PtRegsAArch64` frame to
/// `syscall::dispatch`.
///
/// # SAFETY: `regs` points to a fully-populated `PtRegsAArch64` on
/// the current kernel stack; the kernel owns the frame; userspace
/// can't observe it until `eret` is reached.
/// # C: O(1) + dispatch fn cost
#[no_mangle]
pub unsafe extern "C" fn oxide_dispatch_from_pt_regs_aarch64(regs: *mut PtRegsAArch64) {
    // SAFETY: regs is a kernel-stack pointer to a populated frame
    // per the function contract above; the trampoline guarantees
    // it lives across this call. We need both a read (args+nr) and
    // a write-back (x0) which is why we take `*mut`.
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
        // The trampoline asm uses literal `[sp, #0xNN]` offsets; any
        // reordering breaks the boundary.
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x0),  0x00);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x1),  0x08);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x2),  0x10);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x3),  0x18);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x4),  0x20);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x5),  0x28);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x6),  0x30);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x7),  0x38);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x8),  0x40);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x9),  0x48);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x10), 0x50);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x11), 0x58);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x12), 0x60);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x13), 0x68);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x14), 0x70);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x15), 0x78);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x16), 0x80);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x17), 0x88);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x18), 0x90);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x19), 0x98);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x20), 0xa0);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x21), 0xa8);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x22), 0xb0);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x23), 0xb8);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x24), 0xc0);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x25), 0xc8);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x26), 0xd0);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x27), 0xd8);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x28), 0xe0);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, x29), 0xe8);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, lr),  0xf0);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, sp_el0),   0xf8);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, elr_el1),  0x100);
        assert_eq!(core::mem::offset_of!(PtRegsAArch64, spsr_el1), 0x108);
        assert_eq!(core::mem::size_of::<PtRegsAArch64>(),          0x110);
    }

    #[test]
    fn args_extracted_per_aapcs64_convention() {
        // `15§1.2`: nr=x8; args=x0..x5.
        let regs = PtRegsAArch64 {
            x8: 9,                    // sys_mmap
            x0: 0x1000, x1: 0x4000, x2: 0x7,
            x3: 0x32,   x4: 0x0,    x5: 0x0,
            ..Default::default()
        };
        assert_eq!(regs.syscall_nr(), 9);
        let args = regs.to_syscall_args();
        assert_eq!((args.a0, args.a1, args.a2, args.a3, args.a4, args.a5),
                   (0x1000, 0x4000, 0x7, 0x32, 0x0, 0x0));
    }

    #[test]
    fn dispatch_writes_back_to_x0() {
        let mut regs = PtRegsAArch64::default();
        regs.x8 = 7777; // unimplemented syscall ⇒ ENOSYS
        // SAFETY: hosted test; `regs` is a stack-local PtRegs that
        // lives across this call; the bridge fn reads nr+args and
        // writes x0 — exactly its documented contract.
        unsafe {
            oxide_dispatch_from_pt_regs_aarch64(&mut regs as *mut _);
        }
        // ENOSYS = 38; encoded as `-(38i32 as i64) as u64` per `15§1.3`.
        let expected = -38i64 as u64;
        assert_eq!(regs.x0, expected, "x0 must hold -errno on ENOSYS");
    }
}
