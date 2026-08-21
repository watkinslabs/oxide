// The one x86_64 processor-context record a deep sleep saves and a resume
// restores, plus the pure decisions around it.
//
// Everything firmware does not preserve across S3 is here and nowhere else:
// the control registers, the descriptor-table registers, the segment
// selectors and their MSR bases, and the callee-saved general registers. The
// syscall MSRs are deliberately rebuilt from the live kernel on resume, as
// Linux does, rather than carried in this record. The general-register half
// is a [`PtRegs`] — `54§1.7`
// admits exactly ONE register-frame type per arch, so this record embeds it
// rather than declaring a second GPR layout the rest of the port cannot read.
//
// Layout is asm-coupled: `lowlevel.rs` writes and reads these exact offsets
// through `const` operands derived from `offset_of!`, so a reorder moves the
// asm with the struct and the const asserts below pin the shape.

use crate::pt_regs::PtRegs;

/// Written into the record before the sleep and checked by the resume entry
/// before it jumps anywhere. Firmware that resumes at the waking vector with
/// a record that does not carry this has resumed somewhere unexpected, and
/// the only safe thing left is to stop loudly instead of executing garbage.
pub const SUSPEND_MAGIC: u64 = 0x1de5_1eed_c0de_0001;

/// `lgdt`/`lidt` operand: 2-byte limit then 8-byte linear base
/// (Intel SDM Vol. 3 §2.4.1). Same shape as [`crate::gdt::GdtPointer`],
/// declared here because the record stores both tables' operands as data.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct DescPtr {
    pub limit: u16,
    pub base: u64,
}

/// Everything a deep sleep loses. Field order is the asm contract.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct SavedCpuState {
    /// Callee-saved general registers, the stack pointer and the flags word.
    /// The caller-saved half is dead across the platform enter by the C ABI.
    pub regs: PtRegs,
    /// Where the resume lands: the instruction after the platform enter.
    pub resume_rip: u64,
    /// The stack the resume lands on. Kernel RAM, preserved across S3.
    pub resume_rsp: u64,
    /// [`SUSPEND_MAGIC`] while a sleep is armed.
    pub magic: u64,
    /// What the platform enter returned when it returned at all. Zeroed
    /// before the sleep, so a resume through the waking vector — which never
    /// runs the store — reads it as "the sleep happened".
    pub enter_result: u64,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    /// XCR0 selects the extended register components XSAVE/XRSTOR carry.
    /// Zero means the kernel is using the architectural FXSAVE fallback.
    pub xcr0: u64,
    pub efer: u64,
    /// Page-attribute layout used to interpret every PAT bit in the restored
    /// page tables. Zero means PAT was not enabled on this CPU.
    pub pat: u64,
    /// Vendor CPUID-fault MSR bit for the current thread (0/1).
    pub cpuid_faulting: u64,
    pub fs_base: u64,
    /// `IA32_GS_BASE`: the per-CPU base the kernel dereferences `gs:` through.
    pub gs_base: u64,
    /// `IA32_KERNEL_GS_BASE`: holds the USER base while in kernel mode
    /// (`54§8.5`). Restoring the two the wrong way round leaves ring 3 on
    /// the kernel per-CPU area.
    pub kernel_gs_base: u64,
    pub gdt: DescPtr,
    pub idt: DescPtr,
    pub tr: u16,
    pub ldt: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
}

/// Byte offsets the resume asm addresses this record by.
pub const OFF_REGS_RBX: usize = core::mem::offset_of!(SavedCpuState, regs) + core::mem::offset_of!(PtRegs, rbx);
pub const OFF_REGS_RBP: usize = core::mem::offset_of!(SavedCpuState, regs) + core::mem::offset_of!(PtRegs, rbp);
pub const OFF_REGS_R12: usize = core::mem::offset_of!(SavedCpuState, regs) + core::mem::offset_of!(PtRegs, r12);
pub const OFF_REGS_R13: usize = core::mem::offset_of!(SavedCpuState, regs) + core::mem::offset_of!(PtRegs, r13);
pub const OFF_REGS_R14: usize = core::mem::offset_of!(SavedCpuState, regs) + core::mem::offset_of!(PtRegs, r14);
pub const OFF_REGS_R15: usize = core::mem::offset_of!(SavedCpuState, regs) + core::mem::offset_of!(PtRegs, r15);
pub const OFF_REGS_RSP: usize = core::mem::offset_of!(SavedCpuState, regs) + core::mem::offset_of!(PtRegs, rsp);
pub const OFF_REGS_RFLAGS: usize = core::mem::offset_of!(SavedCpuState, regs) + core::mem::offset_of!(PtRegs, rflags);
pub const OFF_RESUME_RIP: usize = core::mem::offset_of!(SavedCpuState, resume_rip);
pub const OFF_RESUME_RSP: usize = core::mem::offset_of!(SavedCpuState, resume_rsp);
pub const OFF_MAGIC: usize = core::mem::offset_of!(SavedCpuState, magic);
pub const OFF_ENTER_RESULT: usize = core::mem::offset_of!(SavedCpuState, enter_result);
pub const OFF_CR0: usize = core::mem::offset_of!(SavedCpuState, cr0);
pub const OFF_CR2: usize = core::mem::offset_of!(SavedCpuState, cr2);
pub const OFF_CR3: usize = core::mem::offset_of!(SavedCpuState, cr3);
pub const OFF_CR4: usize = core::mem::offset_of!(SavedCpuState, cr4);

const _: () = {
    // The GPR block must be first: the asm reaches it at `state + PtRegs`
    // offsets with no addend.
    assert!(core::mem::offset_of!(SavedCpuState, regs) == 0);
    assert!(OFF_RESUME_RIP == core::mem::size_of::<PtRegs>());
};

/// Highest physical address firmware can resume a real-mode entry point at.
/// The waking vector is a 32-bit physical address and firmware enters it in
/// real mode, where `CS:IP` addresses only the first mebibyte.
pub const REAL_MODE_LIMIT: u64 = 0x10_0000;

/// Page granularity the resume stub is placed at: firmware enters at
/// `CS = pa >> 4, IP = 0` on some machines and `CS = pa >> 12` on others, so
/// the stub is only placeable at an address both readings agree on.
pub const RESUME_PAGE_BYTES: u64 = 4096;

/// Whether `pa` can carry the real-mode resume stub.
///
/// Fail-closed: an address firmware cannot enter is not a resume vector, and
/// a sleep state whose resume vector cannot be published must not be
/// admitted at all (`32a§2` invariant 7).
/// # C: O(1)
pub const fn resume_vector_placeable(pa: u64) -> bool {
    pa != 0 && pa % RESUME_PAGE_BYTES == 0 && pa + RESUME_PAGE_BYTES <= REAL_MODE_LIMIT
}

/// The real-mode segment firmware enters the stub through, for a placeable
/// `pa`. `None` when the address is not placeable at all.
/// # C: O(1)
pub const fn resume_vector_segment(pa: u64) -> Option<u16> {
    if !resume_vector_placeable(pa) { return None; }
    Some((pa >> 4) as u16)
}

impl SavedCpuState {
    /// A record with nothing saved. # C: O(1)
    pub const fn new() -> Self {
        // `PtRegs` has no const constructor; zeroing is the same image its
        // `Default` produces and keeps this usable in a `static`.
        // SAFETY: every field is an integer or a `#[repr(C)]` aggregate of integers, for which the all-zero bit pattern is valid.
        unsafe { core::mem::zeroed() }
    }

    /// Did a resume land here through the armed sleep, rather than firmware
    /// re-entering the waking vector with no sleep of ours in progress?
    /// # C: O(1)
    pub fn armed(&self) -> bool { self.magic == SUSPEND_MAGIC }
}

#[cfg(test)]
#[path = "state/tests.rs"]
mod tests;
