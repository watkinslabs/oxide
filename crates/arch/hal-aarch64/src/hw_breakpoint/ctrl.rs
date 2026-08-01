// DBGBCR<n>_EL1 / DBGWCR<n>_EL1 control-word contract and the full validation
// ladder a per-task hardware-debug slot write runs.
//
// Pure decision logic, no target gate: every branch below is reachable from
// `cargo test -p hal-aarch64`. The hardware-facing loader in `hw.rs` consumes
// the words this file produces and never re-derives a field.

use super::idreg::{ARM_MAX_BRP, ARM_MAX_WRP};

// ---------------------------------------------------------------------------
// Field contract (identical bit positions in DBGBCR and DBGWCR)
// ---------------------------------------------------------------------------

/// `E` — slot enable, bit 0.
pub const CTRL_E: u32 = 1 << 0;
/// `PMC`/`PAC` — privilege/access control, bits 2:1.
pub const CTRL_PRIV_SHIFT: u32 = 1;
/// Width of the privilege field.
pub const CTRL_PRIV_MASK: u32 = 0b11;
/// `LSC` (watchpoints) / breakpoint type, bits 4:3.
pub const CTRL_TYPE_SHIFT: u32 = 3;
/// Width of the type field.
pub const CTRL_TYPE_MASK: u32 = 0b11;
/// `BAS` — byte-address select, bits 12:5.
pub const CTRL_BAS_SHIFT: u32 = 5;
/// Width of the `BAS` field.
pub const CTRL_BAS_MASK: u32 = 0xff;
/// `HMC` — higher mode control, bit 13.
pub const CTRL_HMC: u32 = 1 << 13;
/// `SSC` — security state control, bits 15:14.
pub const CTRL_SSC_SHIFT: u32 = 14;
/// Width of the `SSC` field.
pub const CTRL_SSC_MASK: u32 = 0b11;
/// `LBN` — linked breakpoint number, bits 19:16.
pub const CTRL_LBN_SHIFT: u32 = 16;
/// Width of the `LBN` field.
pub const CTRL_LBN_MASK: u32 = 0xf;
/// `WT` — watchpoint type (linked), bit 20. Watchpoint registers only.
pub const CTRL_WT: u32 = 1 << 20;
/// `MASK` — watchpoint address mask, bits 28:24. Watchpoint registers only.
pub const CTRL_MASK_SHIFT: u32 = 24;
/// Width of the watchpoint `MASK` field.
pub const CTRL_MASK_MASK: u32 = 0x1f;

/// Bits the ptrace hardware-debug ABI carries: `E`, privilege, type, `BAS`.
/// Every bit at or above `HMC` is kernel-owned; a userspace-supplied control
/// word has them dropped rather than refused, so a debugger that writes back
/// a word it never read cannot fail on a field it does not control.
pub const CTRL_USER_MASK: u32 = CTRL_E
    | (CTRL_PRIV_MASK << CTRL_PRIV_SHIFT)
    | (CTRL_TYPE_MASK << CTRL_TYPE_SHIFT)
    | (CTRL_BAS_MASK << CTRL_BAS_SHIFT);

/// Privilege field value selecting EL1 (kernel) matching.
pub const PRIV_EL1: u8 = 1;
/// Privilege field value selecting EL0 (user) matching — the only value a
/// per-task slot may resolve to.
pub const PRIV_EL0: u8 = 2;

/// Type field — instruction execute. The only legal type in a breakpoint
/// register.
pub const TYPE_EXECUTE: u8 = 0;
/// `LSC` — trigger on load.
pub const TYPE_LOAD: u8 = 1;
/// `LSC` — trigger on store.
pub const TYPE_STORE: u8 = 2;
/// `LSC` — trigger on load or store.
pub const TYPE_LOAD_STORE: u8 = TYPE_LOAD | TYPE_STORE;

// `BAS` byte-select patterns. A legal pattern is a contiguous run of set bits;
// its population count is the watched length and its lowest set bit is the
// offset of the first watched byte within the aligned span.
/// `BAS` for one watched byte.
pub const BAS_LEN_1: u8 = 0x01;
/// `BAS` for two watched bytes.
pub const BAS_LEN_2: u8 = 0x03;
/// `BAS` for three watched bytes.
pub const BAS_LEN_3: u8 = 0x07;
/// `BAS` for four watched bytes — the only length an AArch64 instruction
/// breakpoint may use.
pub const BAS_LEN_4: u8 = 0x0f;
/// `BAS` for five watched bytes.
pub const BAS_LEN_5: u8 = 0x1f;
/// `BAS` for six watched bytes.
pub const BAS_LEN_6: u8 = 0x3f;
/// `BAS` for seven watched bytes.
pub const BAS_LEN_7: u8 = 0x7f;
/// `BAS` for eight watched bytes.
pub const BAS_LEN_8: u8 = 0xff;

/// Address alignment an instruction breakpoint is resolved to (one A64
/// instruction).
pub const BRK_ALIGN_MASK: u64 = 0x3;
/// Address alignment a watchpoint is resolved to (one doubleword).
pub const WP_ALIGN_MASK: u64 = 0x7;

/// Which register file a control word is destined for. Decides the legal type
/// values and the address alignment the slot resolves to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegFile {
    /// DBGBVR/DBGBCR — instruction breakpoints.
    Break,
    /// DBGWVR/DBGWCR — data watchpoints.
    Watch,
}

impl RegFile {
    /// Architectural ceiling on this file's slot count.
    /// # C: O(1)
    pub const fn max_slots(self) -> usize {
        match self { RegFile::Break => ARM_MAX_BRP, RegFile::Watch => ARM_MAX_WRP }
    }

    /// Alignment the resolved address is rounded down to.
    /// # C: O(1)
    pub const fn align_mask(self) -> u64 {
        match self { RegFile::Break => BRK_ALIGN_MASK, RegFile::Watch => WP_ALIGN_MASK }
    }
}

/// Why a proposed hardware-debug slot is not installable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HwBpError {
    /// Type/`LSC` value illegal for the destination register file: a
    /// load/store type in a breakpoint slot, or execute in a watchpoint slot.
    Type,
    /// `BAS` is zero — no byte is selected.
    ZeroLen,
    /// `BAS` is not a contiguous run of bytes, so it names no length.
    Len,
    /// `BAS` shifted by the address's offset within its aligned span would
    /// overflow the 8-bit field, which would silently watch fewer bytes than
    /// were asked for.
    LenOverflow,
    /// Requested address arithmetic overflowed the address space.
    Address,
    /// The slot resolves to EL1 privilege because its address is outside the
    /// task's user range; a per-task slot may only match at EL0.
    KernelAddress,
    /// Slot index beyond the implemented register count.
    Slot,
}

/// Decoded control word. Mirrors exactly the four fields the hardware-debug
/// ptrace ABI carries; the kernel-owned fields above `BAS` are not modelled
/// because a task never supplies and never observes them.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Ctrl {
    /// `E` — slot armed.
    pub enabled: bool,
    /// Privilege field (`PRIV_EL0` / `PRIV_EL1`).
    pub privilege: u8,
    /// Type / `LSC`.
    pub kind: u8,
    /// `BAS` byte-select mask.
    pub bas: u8,
}

/// Split a raw control word into its ABI-visible fields. Bits at and above
/// `HMC` are kernel-owned and ignored.
/// # C: O(1)
pub const fn decode(reg: u32) -> Ctrl {
    Ctrl {
        enabled:   reg & CTRL_E != 0,
        privilege: ((reg >> CTRL_PRIV_SHIFT) & CTRL_PRIV_MASK) as u8,
        kind:      ((reg >> CTRL_TYPE_SHIFT) & CTRL_TYPE_MASK) as u8,
        bas:       ((reg >> CTRL_BAS_SHIFT) & CTRL_BAS_MASK) as u8,
    }
}

/// Rebuild a raw control word from decoded fields.
/// # C: O(1)
pub const fn encode(c: Ctrl) -> u32 {
    ((c.bas as u32) << CTRL_BAS_SHIFT)
        | (((c.kind as u32) & CTRL_TYPE_MASK) << CTRL_TYPE_SHIFT)
        | (((c.privilege as u32) & CTRL_PRIV_MASK) << CTRL_PRIV_SHIFT)
        | if c.enabled { CTRL_E } else { 0 }
}

/// Watched length in bytes for a canonical (offset-zero) `BAS` pattern.
/// `None` when the pattern is not a contiguous low-aligned run.
/// # C: O(1)
pub const fn bas_len_bytes(bas: u8) -> Option<u8> {
    match bas {
        BAS_LEN_1 => Some(1),
        BAS_LEN_2 => Some(2),
        BAS_LEN_3 => Some(3),
        BAS_LEN_4 => Some(4),
        BAS_LEN_5 => Some(5),
        BAS_LEN_6 => Some(6),
        BAS_LEN_7 => Some(7),
        BAS_LEN_8 => Some(8),
        _         => None,
    }
}

/// Canonical offset-zero `BAS` pattern for a length in `1..=8`.
/// # C: O(1)
pub const fn bas_for_len(len: u8) -> Option<u8> {
    match len {
        1 => Some(BAS_LEN_1), 2 => Some(BAS_LEN_2), 3 => Some(BAS_LEN_3), 4 => Some(BAS_LEN_4),
        5 => Some(BAS_LEN_5), 6 => Some(BAS_LEN_6), 7 => Some(BAS_LEN_7), 8 => Some(BAS_LEN_8),
        _ => None,
    }
}

/// Generic length + first-watched-byte offset carried by a `BAS` pattern.
/// Rejects a zero mask and any non-contiguous run; a shifted run reports the
/// shift as `offset`.
/// # C: O(1)
pub fn bas_fields(bas: u8) -> Result<(u8, u32), HwBpError> {
    if bas == 0 { return Err(HwBpError::ZeroLen); }
    let offset = bas.trailing_zeros();
    match bas_len_bytes(bas >> offset) {
        Some(len) => Ok((len, offset)),
        None      => Err(HwBpError::Len),
    }
}

/// A validated slot, ready for the register file.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    /// Address written to DBGBVR/DBGWVR — always resolved to the file's
    /// alignment.
    pub addr: u64,
    /// Control word fields written to DBGBCR/DBGWCR.
    pub ctrl: Ctrl,
}

/// Legal type values for a register file.
/// # C: O(1)
pub const fn type_allowed(file: RegFile, kind: u8) -> bool {
    match file {
        RegFile::Break => kind == TYPE_EXECUTE,
        RegFile::Watch => kind != TYPE_EXECUTE,
    }
}

/// A slot matches at EL1: its first watched byte AND its last watched byte
/// both lie at or above the end of the user range. A span that starts inside
/// the user range resolves to EL0 even when its tail crosses the boundary —
/// the hardware simply never matches the kernel bytes at EL0.
/// # C: O(1)
pub const fn in_kernelspace(addr: u64, len: u8, user_end: u64) -> bool {
    let last = addr.saturating_add(len as u64 - 1);
    addr >= user_end && last >= user_end
}

/// Slot resolves to EL0 privilege — the only value a per-task slot may take.
/// # C: O(1)
pub const fn addr_is_user(addr: u64, len: u8, user_end: u64) -> bool {
    !in_kernelspace(addr, len, user_end)
}

/// Validate a task-supplied `(addr, ctrl)` pair and resolve it into the words
/// the register file takes.
///
/// A disabled slot is stored verbatim and validated only when it is armed —
/// a debugger legitimately writes an address before the control word that
/// gives it a length.
///
/// An armed slot resolves as follows. The `BAS` pattern names a length and a
/// byte offset; that offset is added to the address, since a shifted `BAS`
/// means "start `offset` bytes into the aligned span". An instruction
/// breakpoint is then forced to the four-byte length an A64 instruction
/// occupies whatever length was asked for. The address is rounded down to the
/// file's alignment and `BAS` shifted up by the bytes that rounding discarded,
/// which fails if the shift would push watched bytes out of the field. The
/// slot's privilege is derived from the address, never taken from the caller,
/// and a per-task slot that lands outside the user range is refused.
/// # C: O(1)
pub fn parse(file: RegFile, user_ctrl: u32, user_addr: u64, user_end: u64)
    -> Result<Installed, HwBpError>
{
    let c = decode(user_ctrl);
    if !c.enabled {
        return Ok(Installed { addr: user_addr, ctrl: Ctrl { enabled: false, ..c } });
    }
    let (gen_len, bas_off) = bas_fields(c.bas)?;
    if !type_allowed(file, c.kind) { return Err(HwBpError::Type); }

    let addr = match user_addr.checked_add(bas_off as u64) {
        Some(a) => a,
        None    => return Err(HwBpError::Address),
    };
    let len = if file == RegFile::Break { 4 } else { gen_len };
    let bas = match bas_for_len(len) { Some(b) => b, None => return Err(HwBpError::Len) };

    let align = file.align_mask();
    let shift = (addr & align) as u32;
    if ((bas as u32) << shift) > CTRL_BAS_MASK { return Err(HwBpError::LenOverflow); }

    if !addr_is_user(addr, len, user_end) { return Err(HwBpError::KernelAddress); }

    Ok(Installed {
        addr: addr & !align,
        ctrl: Ctrl { enabled: true, privilege: PRIV_EL0, kind: c.kind, bas: (bas << shift) },
    })
}
