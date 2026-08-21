// The EL1 processor state a `SYSTEM_SUSPEND` loses, and the order in which the
// resume entry must put it back (`32a§9`, `54§1`).
//
// UNGATED. The layout, the field set and the restore order are decisions, and a
// decision that only exists inside a `target_arch = "aarch64"` file cannot be
// checked by a hosted run. The asm that consumes this layout lives in
// `cpu_suspend.rs`; the tests below read that file's text and hold the two
// together, which is the only coupling a host can enforce.

/// Marker the resume entry checks before it touches anything else. Firmware
/// that resumes at the wrong address, or at the right address with a stale
/// context identifier, then stops instead of restoring garbage system
/// registers with the MMU off.
pub const OXIDE_SUSPEND_CTX_MAGIC: u64 = 0x5352_5553_504D_4443;

/// Byte offsets of every slot. The resume/save asm indexes the block by these
/// numbers; `layout_matches_offsets` pins them to the struct.
pub const OFF_MAGIC:          usize = 0x00;
pub const OFF_SELF_PA:        usize = 0x08;
pub const OFF_SELF_VA:        usize = 0x10;
pub const OFF_TTBR0_IDENTITY: usize = 0x18;
pub const OFF_MAIR_EL1:       usize = 0x20;
pub const OFF_TCR_EL1:        usize = 0x28;
pub const OFF_TTBR1_EL1:      usize = 0x30;
pub const OFF_SCTLR_EL1:      usize = 0x38;
pub const OFF_TTBR0_EL1:      usize = 0x40;
pub const OFF_VBAR_EL1:       usize = 0x48;
pub const OFF_TPIDR_EL1:      usize = 0x50;
pub const OFF_MDSCR_EL1:      usize = 0x58;
pub const OFF_CPACR_EL1:      usize = 0x60;
pub const OFF_CONTEXTIDR_EL1: usize = 0x68;
pub const OFF_TPIDR_EL0:      usize = 0x70;
pub const OFF_TPIDRRO_EL0:    usize = 0x78;
pub const OFF_SP_EL0:         usize = 0x80;
pub const OFF_X18:            usize = 0x88;
pub const OFF_SP:             usize = 0x90;
pub const OFF_LR:             usize = 0x98;
pub const OFF_FP:             usize = 0xA0;
pub const OFF_X19:            usize = 0xA8;
pub const OFF_X28:            usize = 0xF0;

/// Saved EL1 processor state. 16-byte aligned because it is allocated on the
/// caller's stack and the resume entry reloads `sp` from it.
///
/// Field order is the byte layout: the asm reaches slots by constant offset, so
/// reordering a field silently rewires the resume path.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SuspendCtx {
    /// [`OXIDE_SUSPEND_CTX_MAGIC`], checked first thing on resume.
    pub magic: u64,
    /// Physical address of this block — what firmware is handed as the context
    /// identifier, and what the resume entry dereferences with the MMU off.
    pub self_pa: u64,
    /// Virtual address of this block, picked up once the MMU is back on.
    pub self_va: u64,
    /// Identity translation table installed in `TTBR0_EL1` across the MMU
    /// enable, so the physical PC stays mapped for the one instruction between
    /// `SCTLR_EL1.M` and the branch to the kernel half.
    pub ttbr0_identity_pa: u64,
    pub mair_el1: u64,
    pub tcr_el1: u64,
    pub ttbr1_el1: u64,
    pub sctlr_el1: u64,
    /// The kernel-side `TTBR0_EL1`, installed only after the high branch — the
    /// identity table owns the register until then.
    pub ttbr0_el1: u64,
    pub vbar_el1: u64,
    /// Per-CPU base (`21§7`). Read here, never used as scratch (`54§1.3`).
    pub tpidr_el1: u64,
    pub mdscr_el1: u64,
    pub cpacr_el1: u64,
    pub contextidr_el1: u64,
    pub tpidr_el0: u64,
    pub tpidrro_el0: u64,
    pub sp_el0: u64,
    /// Platform register; the caller's value must survive the sleep.
    pub x18: u64,
    pub sp: u64,
    pub lr: u64,
    pub fp: u64,
    pub x19: u64, pub x20: u64, pub x21: u64, pub x22: u64, pub x23: u64,
    pub x24: u64, pub x25: u64, pub x26: u64, pub x27: u64, pub x28: u64,
    /// Live per-thread permission-overlay rights. This register is outside
    /// FPSIMD and is restored after feature-gated TCR2_EL1 enablement.
    pub por_el0: u64,
}

impl SuspendCtx {
    /// An empty block carrying the magic. Every register slot is filled by the
    /// save asm; the caller fills the addresses.
    /// # C: O(1)
    pub const fn new() -> Self {
        SuspendCtx {
            magic: OXIDE_SUSPEND_CTX_MAGIC,
            self_pa: 0, self_va: 0, ttbr0_identity_pa: 0,
            mair_el1: 0, tcr_el1: 0, ttbr1_el1: 0, sctlr_el1: 0, ttbr0_el1: 0,
            vbar_el1: 0, tpidr_el1: 0, mdscr_el1: 0, cpacr_el1: 0,
            contextidr_el1: 0, tpidr_el0: 0, tpidrro_el0: 0, sp_el0: 0,
            x18: 0, sp: 0, lr: 0, fp: 0,
            x19: 0, x20: 0, x21: 0, x22: 0, x23: 0,
            x24: 0, x25: 0, x26: 0, x27: 0, x28: 0,
            por_el0: 0,
        }
    }

    /// Whether the block carries the resume marker. # C: O(1)
    pub fn magic_ok(&self) -> bool { self.magic == OXIDE_SUSPEND_CTX_MAGIC }
}

/// Every system register the resume entry must put back, paired with its slot
/// offset. The name is the assembler mnemonic, which is what makes the
/// asm-source cross-check possible.
pub const SAVED_SYSREGS: [(&str, usize); 13] = [
    ("mair_el1",       OFF_MAIR_EL1),
    ("tcr_el1",        OFF_TCR_EL1),
    ("ttbr1_el1",      OFF_TTBR1_EL1),
    ("sctlr_el1",      OFF_SCTLR_EL1),
    ("ttbr0_el1",      OFF_TTBR0_EL1),
    ("vbar_el1",       OFF_VBAR_EL1),
    ("tpidr_el1",      OFF_TPIDR_EL1),
    ("mdscr_el1",      OFF_MDSCR_EL1),
    ("cpacr_el1",      OFF_CPACR_EL1),
    ("contextidr_el1", OFF_CONTEXTIDR_EL1),
    ("tpidr_el0",      OFF_TPIDR_EL0),
    ("tpidrro_el0",    OFF_TPIDRRO_EL0),
    ("sp_el0",         OFF_SP_EL0),
];

/// The registers that must be in place before the MMU is turned back on. The
/// translation-table bases, the translation control and the memory-attribute
/// register describe the tables `SCTLR_EL1.M` is about to start walking; a
/// resume that sets `M` first walks whatever the reset values point at.
pub const PRE_MMU_SYSREGS: [&str; 4] = ["mair_el1", "tcr_el1", "ttbr0_el1", "ttbr1_el1"];

/// The registers restored only after the branch into the kernel half, once the
/// identity table has done its job.
pub const POST_MMU_SYSREGS: [&str; 9] = [
    "ttbr0_el1", "vbar_el1", "tpidr_el1", "mdscr_el1", "cpacr_el1",
    "contextidr_el1", "tpidr_el0", "tpidrro_el0", "sp_el0",
];

#[cfg(test)]
#[path = "cpu_suspend_ctx/tests.rs"]
mod tests;
