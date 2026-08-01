// DR7 (debug control) bit contract + the per-task validation ladder.
//
// ONE owner of every DR7 field constant in this crate: the diagnostic
// watchpoint helpers in `regs.rs` and the per-task ptrace layer both name
// constants from here (`07§5`). Pure decision logic — no target gate, so
// `cargo test -p hal-x86_64` exercises every branch.

/// Hardware debug-address registers: DR0-DR3.
pub const HBP_NUM: usize = 4;

/// DR7.L0 — local-enable DR0 (bit 0).
pub const DR7_L0: u64 = 1 << 0;
/// DR7.G0 — global-enable DR0 (bit 1).
pub const DR7_G0: u64 = 1 << 1;
/// DR7.L1 — local-enable DR1 (bit 2).
pub const DR7_L1: u64 = 1 << 2;
/// DR7.LE — local exact-match (bit 8).
pub const DR7_LE: u64 = 1 << 8;
/// DR7.GE — global exact data-breakpoint match (bit 9).
pub const DR7_GE: u64 = 1 << 9;
/// DR7 bit 10 — reserved, read-as-one; software keeps it set.
pub const DR7_RESERVED_ONE: u64 = 1 << 10;
/// DR7.GD — general detect (bit 13). A user task may never set it: it turns
/// every later debug-register access into a #DB, which would trap the kernel's
/// own context-switch reload. Rejected here.
pub const DR7_GD: u64 = 1 << 13;
/// DR7 bits that must read zero: 11, 12, 14, 15 and the whole upper half.
/// Bit 13 (GD) is excluded so it reports as its own error; bit 10 is
/// reserved-ONE and excluded likewise.
pub const DR7_RESERVED_ZERO: u64 = 0xFFFF_FFFF_0000_D800;
/// Every local+global enable bit (bits 0-7): non-zero ⇒ at least one slot armed.
pub const DR7_ENABLE_MASK: u64 = 0x0000_0000_0000_00FF;
/// DR7 with no slot armed — the architectural reset value.
pub const DR7_EMPTY: u64 = DR7_RESERVED_ONE;

/// R/Wn — break on instruction EXECUTE.
pub const DR7_RW_EXECUTE: u64 = 0b00;
/// R/Wn — break on data WRITE only.
pub const DR7_RW_WRITE: u64 = 0b01;
/// R/Wn — break on I/O read/write. Legal only with CR4.DE; refused for tasks.
pub const DR7_RW_IO: u64 = 0b10;
/// R/Wn — break on data READ or WRITE.
pub const DR7_RW_READWRITE: u64 = 0b11;
/// R/Wn field width mask.
pub const DR7_RW_MASK: u64 = 0b11;

/// LENn — 1 byte.
pub const DR7_LEN_1: u64 = 0b00;
/// LENn — 2 bytes.
pub const DR7_LEN_2: u64 = 0b01;
/// LENn — 8 bytes (64-bit mode only).
pub const DR7_LEN_8: u64 = 0b10;
/// LENn — 4 bytes.
pub const DR7_LEN_4: u64 = 0b11;
/// LENn field width mask.
pub const DR7_LEN_MASK: u64 = 0b11;

/// Bit index of R/W0; each further slot is 4 bits up.
pub const DR7_RW0_SHIFT: u32 = 16;
/// Bit index of LEN0; each further slot is 4 bits up.
pub const DR7_LEN0_SHIFT: u32 = 18;
/// Bits per slot in the DR7 control half.
pub const DR7_SLOT_SHIFT: u32 = 4;

/// Bit index of slot `i`'s R/W field.
/// # C: O(1)
pub const fn rw_shift(slot: usize) -> u32 { DR7_RW0_SHIFT + (slot as u32) * DR7_SLOT_SHIFT }

/// Bit index of slot `i`'s LEN field.
/// # C: O(1)
pub const fn len_shift(slot: usize) -> u32 { DR7_LEN0_SHIFT + (slot as u32) * DR7_SLOT_SHIFT }

/// Slot `i`'s local-enable bit (bit `2i`).
/// # C: O(1)
pub const fn local_enable(slot: usize) -> u64 { DR7_L0 << (slot * 2) }

/// Slot `i`'s global-enable bit (bit `2i+1`).
/// # C: O(1)
pub const fn global_enable(slot: usize) -> u64 { DR7_G0 << (slot * 2) }

/// Slot `i` armed by either enable bit.
/// # C: O(1)
pub const fn slot_enabled(dr7: u64, slot: usize) -> bool {
    dr7 & (local_enable(slot) | global_enable(slot)) != 0
}

/// Slot `i`'s R/W encoding.
/// # C: O(1)
pub const fn slot_rw(dr7: u64, slot: usize) -> u64 { (dr7 >> rw_shift(slot)) & DR7_RW_MASK }

/// Slot `i`'s LEN encoding.
/// # C: O(1)
pub const fn slot_len(dr7: u64, slot: usize) -> u64 { (dr7 >> len_shift(slot)) & DR7_LEN_MASK }

/// Watched span in bytes for a LEN encoding.
/// # C: O(1)
pub const fn len_bytes(len: u64) -> u64 {
    match len & DR7_LEN_MASK {
        DR7_LEN_1 => 1,
        DR7_LEN_2 => 2,
        DR7_LEN_8 => 8,
        _         => 4,
    }
}

/// Why a proposed DR7 (or breakpoint address) is not installable.
/// `slot` names the offending DR0-DR3 index so a ptrace caller can report it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Dr7Error {
    /// DR7.GD requested — general detect is kernel-owned.
    GeneralDetect,
    /// A reserved-zero DR7 bit was set.
    Reserved,
    /// R/W = I/O breakpoint, which requires CR4.DE and is never granted.
    IoBreakpoint { slot: usize },
    /// Execute breakpoint with LEN != 1 byte.
    ExecuteLen { slot: usize },
    /// Breakpoint address not aligned to its watched length.
    Misaligned { slot: usize },
    /// Breakpoint address is outside the task's user address range.
    KernelAddress { slot: usize },
}

/// Linux's DR7 write ladder: reject GD and reserved-zero bits, then validate
/// only the slots an enable bit actually arms. Returns the installable DR7
/// (reserved-one bit forced set); `addrs` supplies DR0-DR3 for the alignment
/// and user-range tests, `user_end` is the first non-user virtual address.
/// # C: O(HBP_NUM)
pub fn validate_dr7(dr7: u64, addrs: &[u64; HBP_NUM], user_end: u64) -> Result<u64, Dr7Error> {
    if dr7 & DR7_GD != 0 { return Err(Dr7Error::GeneralDetect); }
    if dr7 & DR7_RESERVED_ZERO != 0 { return Err(Dr7Error::Reserved); }
    let mut slot = 0;
    while slot < HBP_NUM {
        if slot_enabled(dr7, slot) {
            let rw = slot_rw(dr7, slot);
            let len = slot_len(dr7, slot);
            if rw == DR7_RW_IO { return Err(Dr7Error::IoBreakpoint { slot }); }
            if rw == DR7_RW_EXECUTE && len != DR7_LEN_1 { return Err(Dr7Error::ExecuteLen { slot }); }
            let span = if rw == DR7_RW_EXECUTE { 1 } else { len_bytes(len) };
            let addr = addrs[slot];
            if addr & (span - 1) != 0 { return Err(Dr7Error::Misaligned { slot }); }
            if !addr_fits_user(addr, span, user_end) { return Err(Dr7Error::KernelAddress { slot }); }
        }
        slot += 1;
    }
    Ok(dr7 | DR7_RESERVED_ONE)
}

/// Whole `[addr, addr+span)` span lies below `user_end` without wrapping.
/// # C: O(1)
pub const fn addr_fits_user(addr: u64, span: u64, user_end: u64) -> bool {
    match addr.checked_add(span) {
        Some(end) => end <= user_end,
        None      => false,
    }
}

/// Guard for a DR0-DR3 address write ahead of any DR7 arming: a task may only
/// name userspace. Length is unknown at this point, so the single byte at
/// `addr` must be in range.
/// # C: O(1)
pub fn validate_addr(slot: usize, addr: u64, user_end: u64) -> Result<(), Dr7Error> {
    if addr_fits_user(addr, 1, user_end) { Ok(()) } else { Err(Dr7Error::KernelAddress { slot }) }
}
