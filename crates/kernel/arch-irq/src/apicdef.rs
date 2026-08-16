// Local-APIC and I/O-APIC register layout (x86_64).
//
// Ungated on purpose: the numbers are architectural, and the state save/restore
// that consumes them (`pm::lapic_state`, `pm::ioapic_state`) must be testable
// on the host. The gated register accessors in `lapic::regs` re-export from
// here rather than keeping a second copy — one wrong offset in a duplicate set
// is a machine that resumes with its timer pointed at the wrong vector.

// ---- Local APIC, offsets from the APIC page base ---------------------------

pub const REG_ID:          usize = 0x020;
pub const REG_VERSION:     usize = 0x030;
pub const REG_TASKPRI:     usize = 0x080;
pub const REG_EOI:         usize = 0x0B0;
pub const REG_LDR:         usize = 0x0D0;
pub const REG_DFR:         usize = 0x0E0;
pub const REG_SVR:         usize = 0x0F0;
pub const REG_ESR:         usize = 0x280;
pub const REG_ICR_LO:      usize = 0x300;
pub const REG_LVT_CMCI:    usize = 0x2F0;
pub const REG_LVT_TIMER:   usize = 0x320;
pub const REG_LVT_THERMAL: usize = 0x330;
pub const REG_LVT_PERF:    usize = 0x340;
pub const REG_LVT_LINT0:   usize = 0x350;
pub const REG_LVT_LINT1:   usize = 0x360;
pub const REG_LVT_ERROR:   usize = 0x370;
pub const REG_TIMER_INIT:  usize = 0x380;
pub const REG_TIMER_CUR:   usize = 0x390;
pub const REG_TIMER_DIV:   usize = 0x3E0;

/// SVR bit 8: APIC software enable.
pub const SVR_ENABLE: u32 = 1 << 8;
/// LVT bit 16: the entry is masked.
pub const LVT_MASKED: u32 = 1 << 16;
/// Version-register field holding the highest LVT entry index.
pub const VERSION_MAXLVT_SHIFT: u32 = 16;
pub const VERSION_MAXLVT_MASK: u32 = 0xFF;

/// Highest LVT entry index this APIC implements, from its version register.
/// # C: O(1)
pub const fn maxlvt(version: u32) -> u32 {
    (version >> VERSION_MAXLVT_SHIFT) & VERSION_MAXLVT_MASK
}

/// LVT index at which the performance-counter entry exists.
pub const MAXLVT_PERF: u32 = 4;
/// LVT index at which the thermal-sensor entry exists.
pub const MAXLVT_THERMAL: u32 = 5;
/// LVT index at which the corrected-machine-check entry exists.
pub const MAXLVT_CMCI: u32 = 6;

// ---- I/O APIC, indirect register indices -----------------------------------

/// Index register in the controller's memory window.
pub const IOAPIC_IOREGSEL: usize = 0x00;
/// Data window paired with the index register.
pub const IOAPIC_IOWIN: usize = 0x10;

/// Identification register index.
pub const IOAPIC_REG_ID: u32 = 0x00;
/// Version register index; its high half holds the highest redirection entry.
pub const IOAPIC_REG_VERSION: u32 = 0x01;
/// First redirection-table register index. Each entry is two consecutive
/// registers, low half first.
pub const IOAPIC_REG_REDIR_BASE: u32 = 0x10;

/// The identification register's ID field.
pub const IOAPIC_ID_SHIFT: u32 = 24;
pub const IOAPIC_ID_MASK: u32 = 0xFF;

/// Redirection-entry bit 16: the entry is masked.
pub const IOAPIC_REDIR_MASKED: u32 = 1 << 16;

/// Register index of redirection entry `pin`'s low half. # C: O(1)
pub const fn redir_lo(pin: u32) -> u32 { IOAPIC_REG_REDIR_BASE + 2 * pin }
/// Register index of redirection entry `pin`'s high half. # C: O(1)
pub const fn redir_hi(pin: u32) -> u32 { IOAPIC_REG_REDIR_BASE + 2 * pin + 1 }

/// Highest redirection entry this controller implements, from its version
/// register. # C: O(1)
pub const fn max_redir(version: u32) -> u32 { (version >> 16) & 0xFF }
