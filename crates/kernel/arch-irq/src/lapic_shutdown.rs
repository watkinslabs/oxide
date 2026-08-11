// Taking the local APIC down, and handing the interrupt hardware back in the
// state firmware left it in.
//
// Two distinct operations that always run as a pair, in this order:
//
// 1. SHUTDOWN — every local-vector-table entry masked and the APIC software
//    disabled. After it, this CPU's local APIC asserts nothing.
// 2. BOOT INTERRUPT MODE — the APIC software-enabled again on the spurious
//    vector, `LVT0` delivering ExtINT and `LVT1` delivering NMI. That is the
//    virtual-wire arrangement a machine powers on in: legacy 8259 interrupts
//    and NMI reach the bootstrap processor through the local APIC without any
//    software having programmed a redirection table.
//
// Step 2 exists because whatever runs next did not program this hardware and
// is entitled to find it as firmware left it. A kernel handed a fully masked
// APIC gets no timer tick until it has brought up its own interrupt
// controller, and one that expects legacy delivery before that point never
// gets it at all.
//
// Every value written is decided by the ungated functions below so the encoding
// is checkable without a machine: this path runs at most once per boot, on the
// way out, with nothing left able to report that it got a bit wrong.
//
// WHY THIS IS A TOP-LEVEL MODULE and not a child of `lapic`. That module is
// compiled only into the kernel target, so a `#[cfg(test)]` block anywhere
// inside it is silently discarded — the tests below would build on no target
// and run on none. Only `apply`, which touches registers, carries the gate.

pub mod apply;


/// LAPIC version register. Bits 23:16 give the index of the highest
/// local-vector-table entry this implementation has.
pub const REG_VERSION: usize = 0x030;
/// Spurious-interrupt vector register.
pub const REG_SPURIOUS: usize = 0x0F0;
/// Error-status register.
pub const REG_ERROR_STATUS: usize = 0x280;
/// LVT: corrected machine-check interrupt.
pub const REG_LVT_CMCI: usize = 0x2F0;
/// LVT: timer.
pub const REG_LVT_TIMER: usize = 0x320;
/// LVT: thermal sensor.
pub const REG_LVT_THERMAL: usize = 0x330;
/// LVT: performance counter.
pub const REG_LVT_PERF: usize = 0x340;
/// LVT: local interrupt 0 — the legacy interrupt pin.
pub const REG_LVT0: usize = 0x350;
/// LVT: local interrupt 1 — the NMI pin.
pub const REG_LVT1: usize = 0x360;
/// LVT: APIC error.
pub const REG_LVT_ERROR: usize = 0x370;

/// Return the x2APIC MSR corresponding to one 16-byte LAPIC register offset.
/// # C: O(1)
pub const fn x2apic_msr_for_offset(offset: usize) -> Option<u32> {
    if offset & 0xf != 0 || offset >= 4096 { return None; }
    Some(0x800 + (offset >> 4) as u32)
}

/// LVT bit 16 — masked.
pub const LVT_MASKED: u32 = 1 << 16;
/// LVT bit 15 — level triggered.
pub const LVT_LEVEL_TRIGGER: u32 = 1 << 15;
/// LVT bit 14 — remote IRR. Hardware-owned status; writes are discarded.
pub const LVT_REMOTE_IRR: u32 = 1 << 14;
/// LVT bit 13 — input polarity, active low.
pub const LVT_INPUT_POLARITY: u32 = 1 << 13;
/// LVT bit 12 — send pending. Hardware-owned status; writes are discarded.
pub const LVT_SEND_PENDING: u32 = 1 << 12;
/// LVT bits 10:8 — delivery mode.
pub const LVT_MODE_MASK: u32 = 0x700;
/// Delivery mode 100 — NMI.
pub const LVT_MODE_NMI: u32 = 4 << 8;
/// Delivery mode 111 — ExtINT, i.e. take the vector off the legacy PIC.
pub const LVT_MODE_EXTINT: u32 = 7 << 8;

/// Spurious-vector register bit 8 — APIC software enable.
pub const SPURIOUS_ENABLE: u32 = 1 << 8;
/// Vector field of any LVT or of the spurious-vector register.
pub const VECTOR_MASK: u32 = 0xFF;

/// Spurious vector left behind for whatever runs next. The low four bits of
/// this field are hardwired to one on the oldest implementations, so `0xF` is
/// the lowest value every implementation can actually hold.
pub const BOOT_SPURIOUS_VECTOR: u32 = 0xF;

/// Highest LVT index this implementation provides.
/// # C: O(1)
pub fn max_lvt(version: u32) -> u32 { (version >> 16) & 0xFF }

/// The LVT registers to mask, in order, each with the `max_lvt` it needs.
///
/// The error entry goes FIRST: masking any other entry can make the APIC raise
/// an error, and an unmasked error entry would deliver it into a machine that
/// is being taken apart. The remainder are ordered by index.
pub const LVT_MASK_ORDER: [(usize, u32); 7] = [
    (REG_LVT_ERROR, 3),
    (REG_LVT_TIMER, 0),
    (REG_LVT0, 0),
    (REG_LVT1, 0),
    (REG_LVT_PERF, 4),
    (REG_LVT_THERMAL, 5),
    (REG_LVT_CMCI, 6),
];

/// The LVT registers rewritten to a flat masked word once every entry is
/// masked, so nothing carries a stale vector or trigger mode into the next
/// kernel. Only the entries every implementation with that `max_lvt` has.
pub const LVT_CLEAN_ORDER: [(usize, u32); 5] = [
    (REG_LVT_TIMER, 0),
    (REG_LVT0, 0),
    (REG_LVT1, 0),
    (REG_LVT_ERROR, 3),
    (REG_LVT_PERF, 4),
];

/// Is the LVT entry needing `min_lvt` present on an implementation reporting
/// `maxlvt`?
/// # C: O(1)
pub fn lvt_present(maxlvt: u32, min_lvt: u32) -> bool { maxlvt >= min_lvt }

/// Mask an LVT entry without disturbing the rest of it.
/// # C: O(1)
pub fn lvt_masked(cur: u32) -> u32 { cur | LVT_MASKED }

/// The spurious-vector word with the APIC software-disabled.
/// # C: O(1)
pub fn spurious_disabled(cur: u32) -> u32 { cur & !SPURIOUS_ENABLE }

/// The spurious-vector word for boot interrupt mode: APIC software-enabled
/// again, on [`BOOT_SPURIOUS_VECTOR`].
///
/// Enabled is the point. `LVT0` and `LVT1` deliver nothing at all while the
/// APIC is software-disabled, so writing the virtual-wire entries without this
/// leaves the machine exactly as deaf as a full shutdown.
/// # C: O(1)
pub fn spurious_boot_mode(cur: u32) -> u32 {
    (cur & !VECTOR_MASK) | SPURIOUS_ENABLE | BOOT_SPURIOUS_VECTOR
}

/// Rewrite one LVT entry for boot interrupt mode: edge triggered, active high,
/// unmasked, delivering `mode`.
///
/// Bits 12 and 14 are hardware-owned status bits. They are left in the written
/// word rather than masked out, because the hardware discards them either way
/// and the value this kernel leaves behind is then bit-identical to the one
/// every other producer of this state writes.
/// # C: O(1)
fn boot_mode_lvt(cur: u32, mode: u32) -> u32 {
    let kept = cur
        & !(LVT_MODE_MASK
            | LVT_SEND_PENDING
            | LVT_INPUT_POLARITY
            | LVT_REMOTE_IRR
            | LVT_LEVEL_TRIGGER
            | LVT_MASKED);
    kept | LVT_REMOTE_IRR | LVT_SEND_PENDING | mode
}

/// `LVT0` delivering ExtINT — the legacy interrupt line reaches this CPU.
/// # C: O(1)
pub fn lvt0_boot_mode(cur: u32) -> u32 { boot_mode_lvt(cur, LVT_MODE_EXTINT) }

/// `LVT1` delivering NMI.
/// # C: O(1)
pub fn lvt1_boot_mode(cur: u32) -> u32 { boot_mode_lvt(cur, LVT_MODE_NMI) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_error_entry_is_masked_before_any_other() {
        // Masking an entry can itself raise an APIC error; an unmasked error
        // entry would then deliver an interrupt into a machine being torn down.
        assert_eq!(LVT_MASK_ORDER[0].0, REG_LVT_ERROR);
    }

    #[test]
    fn every_masked_entry_names_the_implementation_that_has_it() {
        // An entry masked on an implementation that does not have it is a
        // write to a reserved register.
        for (reg, min) in LVT_MASK_ORDER {
            match reg {
                REG_LVT_TIMER | REG_LVT0 | REG_LVT1 => assert_eq!(min, 0),
                REG_LVT_ERROR => assert_eq!(min, 3),
                REG_LVT_PERF => assert_eq!(min, 4),
                REG_LVT_THERMAL => assert_eq!(min, 5),
                REG_LVT_CMCI => assert_eq!(min, 6),
                other => assert!(false, "unclassified LVT register {other:#x}"),
            }
        }
        assert!(!lvt_present(2, 3));
        assert!(lvt_present(3, 3));
        assert!(!lvt_present(5, 6));
    }

    #[test]
    fn the_clean_pass_never_touches_an_entry_the_mask_pass_skipped() {
        // A flat write to an absent register is the same defect as masking one.
        for (reg, min) in LVT_CLEAN_ORDER {
            let found = LVT_MASK_ORDER.iter().find(|(r, _)| *r == reg);
            let (_, mask_min) = found.expect("cleaned entry is also masked");
            assert_eq!(*mask_min, min, "the two passes disagree on {reg:#x}");
        }
    }

    #[test]
    fn max_lvt_reads_bits_23_through_16() {
        assert_eq!(max_lvt(0x0005_0014), 5);
        assert_eq!(max_lvt(0x00FF_0000), 0xFF);
        // The version byte below it must not leak into the answer.
        assert_eq!(max_lvt(0x0000_0014), 0);
    }

    #[test]
    fn masking_an_entry_preserves_everything_else_in_it() {
        let cur = LVT_MODE_EXTINT | LVT_LEVEL_TRIGGER | 0x33;
        assert_eq!(lvt_masked(cur), cur | LVT_MASKED);
        assert_eq!(lvt_masked(cur) & VECTOR_MASK, 0x33);
        assert!(lvt_masked(cur) & LVT_MASKED != 0);
    }

    #[test]
    fn shutdown_clears_only_the_software_enable() {
        let cur = SPURIOUS_ENABLE | 0xFF;
        assert_eq!(spurious_disabled(cur), 0xFF);
        // Already disabled stays disabled rather than toggling.
        assert_eq!(spurious_disabled(0xFF), 0xFF);
    }

    #[test]
    fn boot_mode_re_enables_the_apic_on_the_low_spurious_vector() {
        // Leaving it disabled is the defect that makes the two virtual-wire
        // entries below inert: a software-disabled APIC delivers neither.
        let v = spurious_boot_mode(0);
        assert!(v & SPURIOUS_ENABLE != 0, "boot mode must software-enable the APIC");
        assert_eq!(v & VECTOR_MASK, BOOT_SPURIOUS_VECTOR);
        // The previous vector must not survive underneath the new one.
        assert_eq!(spurious_boot_mode(0xFF) & VECTOR_MASK, BOOT_SPURIOUS_VECTOR);
    }

    #[test]
    fn the_legacy_pin_is_left_unmasked_edge_triggered_and_active_high() {
        // Every one of these is separately load-bearing: masked delivers
        // nothing, level-triggered latches an assertion nothing will ever
        // acknowledge, and active-low inverts a line that is not inverted.
        let v = lvt0_boot_mode(LVT_MASKED | LVT_LEVEL_TRIGGER | LVT_INPUT_POLARITY | 0x20);
        assert_eq!(v & LVT_MASKED, 0);
        assert_eq!(v & LVT_LEVEL_TRIGGER, 0);
        assert_eq!(v & LVT_INPUT_POLARITY, 0);
        assert_eq!(v & LVT_MODE_MASK, LVT_MODE_EXTINT);
    }

    #[test]
    fn the_nmi_pin_delivers_nmi_and_nothing_else() {
        let v = lvt1_boot_mode(LVT_MASKED | LVT_MODE_EXTINT);
        assert_eq!(v & LVT_MODE_MASK, LVT_MODE_NMI);
        assert_eq!(v & LVT_MASKED, 0);
        // The two pins must not be handed the same delivery mode.
        assert_ne!(lvt0_boot_mode(0) & LVT_MODE_MASK, lvt1_boot_mode(0) & LVT_MODE_MASK);
    }

    #[test]
    fn the_delivery_modes_sit_in_bits_10_through_8() {
        assert_eq!(LVT_MODE_MASK, 0x700);
        assert_eq!(LVT_MODE_NMI, 0x400);
        assert_eq!(LVT_MODE_EXTINT, 0x700);
        assert_eq!(LVT_MODE_NMI & !LVT_MODE_MASK, 0);
        assert_eq!(LVT_MODE_EXTINT & !LVT_MODE_MASK, 0);
    }

    #[test]
    fn the_vector_field_and_the_status_bits_do_not_overlap() {
        for bit in [LVT_MASKED, LVT_LEVEL_TRIGGER, LVT_REMOTE_IRR,
                    LVT_INPUT_POLARITY, LVT_SEND_PENDING, SPURIOUS_ENABLE] {
            assert_eq!(bit & VECTOR_MASK, 0);
        }
        assert_eq!(LVT_MODE_MASK & VECTOR_MASK, 0);
    }

    #[test]
    fn x2apic_register_offsets_select_the_paired_msr_bank() {
        assert_eq!(x2apic_msr_for_offset(0x020), Some(0x802));
        assert_eq!(x2apic_msr_for_offset(0x0B0), Some(0x80B));
        assert_eq!(x2apic_msr_for_offset(0x300), Some(0x830));
        assert_eq!(x2apic_msr_for_offset(0x001), None);
        assert_eq!(x2apic_msr_for_offset(4096), None);
    }
}
