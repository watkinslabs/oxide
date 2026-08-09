use super::*;

#[test]
fn the_access_byte_marks_a_present_ring0_system_ldt() {
    // P=1 (0x80), DPL=0, S=0 (system, not code/data), type=2 (LDT).
    assert_eq!(ACCESS_LDT, 0x82);
    assert_eq!(ACCESS_LDT & 0x80, 0x80, "present");
    assert_eq!((ACCESS_LDT >> 5) & 0x3, 0, "DPL=0");
    assert_eq!((ACCESS_LDT >> 4) & 0x1, 0, "S=0 (system descriptor)");
    assert_eq!(ACCESS_LDT & 0xF, 0x2, "type = LDT");
}

#[test]
fn the_descriptor_packs_base_and_limit_across_both_halves() {
    let base: u64 = 0xFFFF_8000_1234_5678;
    let lo = ldt_low(base, ldt_limit(8192));
    let hi = ldt_high(base);
    assert_eq!(lo & 0xFFFF, 0xFFFF, "limit[15:0] = 65535");
    assert_eq!((lo >> 16) & 0xFF_FFFF, 0x34_5678, "base[23:0]");
    assert_eq!((lo >> 40) & 0xFF, ACCESS_LDT as u64);
    assert_eq!((lo >> 48) & 0xF, 0, "limit[19:16]");
    assert_eq!((lo >> 52) & 0xF, 0, "byte granularity");
    assert_eq!((lo >> 56) & 0xFF, 0x12, "base[31:24]");
    assert_eq!(hi, 0xFFFF_8000, "base[63:32]");
}

#[test]
fn the_limit_covers_the_last_byte_of_the_last_entry() {
    // Off by one either way is a real bug: one short hides the top entry
    // behind a #GP, one long exposes eight bytes past the table.
    assert_eq!(ldt_limit(1), 7);
    assert_eq!(ldt_limit(2), 15);
    assert_eq!(ldt_limit(LDT_ENTRIES), LDT_ENTRIES * LDT_ENTRY_SIZE - 1);
    assert_eq!(ldt_limit(LDT_ENTRIES), 65535);
}

#[test]
fn every_cpu_owns_a_distinct_descriptor_pair() {
    // One shared GDT means a single LDT index would let two CPUs running
    // different address spaces overwrite each other's base.
    let mut seen = [0u16; crate::tss::NR_TSS];
    for cpu in 0..crate::tss::NR_TSS {
        let sel = ldt_selector(cpu);
        assert_eq!(sel & 0x7, 0, "selector names a GDT entry at RPL 0");
        assert!(!seen[..cpu].contains(&sel), "cpu {cpu} reuses selector {sel:#x}");
        seen[cpu] = sel;
    }
    // And the whole run must sit inside the GDT.
    let last = gdt::LDT_GDT_INDEX_BASE + (crate::tss::NR_TSS - 1) * 2 + 1;
    assert!(last < gdt::GDT_LEN, "LDT descriptors overflow the GDT");
}

#[test]
fn ldt_descriptors_do_not_overlap_the_tss_descriptors() {
    // The TSS run is [10, 10 + NR_TSS*2); the LDT run starts exactly where it
    // ends. An overlap would make `ltr` and `lldt` fight over one pair.
    assert_eq!(gdt::LDT_GDT_INDEX_BASE, 10 + crate::tss::NR_TSS * 2);
    assert_eq!(ldt_selector(0) as usize, gdt::LDT_GDT_INDEX_BASE * 8);
}

#[test]
fn the_load_token_distinguishes_generation_zero_from_nothing_loaded() {
    assert_ne!(load_token(0), 0, "a loaded table must never look unloaded");
    assert_ne!(load_token(1), load_token(2));
}

#[test]
fn a_fresh_cpu_reports_no_ldt_loaded() {
    assert_eq!(current_token(crate::tss::NR_TSS - 1), 0);
}
