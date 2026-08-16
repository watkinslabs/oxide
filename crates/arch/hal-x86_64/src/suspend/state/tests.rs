// Provenance for the processor-context record: what a deep sleep must save,
// where the asm finds it, and which physical addresses firmware can resume a
// real-mode stub at.

use super::*;

/// Every control register, MSR and descriptor the record must carry, named
/// once. A restore that drops one of these leaves the CPU running on
/// firmware's value, which on S3 means "whatever the platform reset to".
fn saved_words(s: &SavedCpuState) -> [(&'static str, u64); 16] {
    [
        ("cr0", s.cr0), ("cr2", s.cr2), ("cr3", s.cr3), ("cr4", s.cr4),
        ("efer", s.efer), ("star", s.star), ("lstar", s.lstar),
        ("cstar", s.cstar), ("sfmask", s.sfmask),
        ("fs_base", s.fs_base), ("gs_base", s.gs_base), ("kernel_gs_base", s.kernel_gs_base),
        ("gdt", s.gdt.base), ("idt", s.idt.base),
        ("tr", s.tr as u64), ("ldt", s.ldt as u64),
    ]
}

#[test]
fn the_record_round_trips_every_word_a_deep_sleep_loses() {
    let mut s = SavedCpuState::new();
    // Distinct values so a field that aliases another is visible.
    s.cr0 = 0x8005_0033; s.cr2 = 0x1111; s.cr3 = 0x2000; s.cr4 = 0x3406b0;
    s.efer = 0xd01; s.star = 0x0023_0010_0000_0000; s.lstar = 0xffff_ffff_8100_1000;
    s.cstar = 0xffff_ffff_8100_2000; s.sfmask = 0x4_0700;
    s.fs_base = 0x7fff_0000_0000; s.gs_base = 0xffff_8000_0001_0000;
    s.kernel_gs_base = 0x7fff_0000_1000;
    s.gdt = DescPtr { limit: 0x7f, base: 0xffff_ffff_8200_0000 };
    s.idt = DescPtr { limit: 0xfff, base: 0xffff_ffff_8300_0000 };
    s.tr = 0x50; s.ldt = 0x60; s.ds = 0x30; s.es = 0x30; s.fs = 0; s.gs = 0;

    let words = saved_words(&s);
    for (name, value) in words {
        assert_ne!(value, 0, "{name} did not survive the record");
    }
    // No two fields share storage: sixteen distinct values must stay distinct.
    for i in 0..words.len() {
        for j in (i + 1)..words.len() {
            assert_ne!(words[i].1, words[j].1, "{} aliases {}", words[i].0, words[j].0);
        }
    }
    // Selectors are stored beside the bases, not instead of them.
    assert_eq!(s.tr, 0x50);
    assert_eq!(s.ldt, 0x60);
    assert_eq!(s.ds, 0x30);
}

#[test]
fn the_callee_saved_registers_live_in_the_one_frame_type() {
    // `54§1.7`: one register-frame type per arch. The record embeds `PtRegs`
    // at offset zero rather than declaring a second GPR layout.
    assert_eq!(core::mem::offset_of!(SavedCpuState, regs), 0);
    let mut s = SavedCpuState::new();
    s.regs.rbx = 1; s.regs.rbp = 2; s.regs.r12 = 3;
    s.regs.r13 = 4; s.regs.r14 = 5; s.regs.r15 = 6;
    s.regs.rsp = 7; s.regs.rflags = 8;
    assert_eq!((s.regs.rbx, s.regs.rbp, s.regs.r12, s.regs.r13, s.regs.r14, s.regs.r15), (1, 2, 3, 4, 5, 6));
    assert_eq!((s.regs.rsp, s.regs.rflags), (7, 8));
}

#[test]
fn the_asm_offsets_address_the_fields_they_name() {
    let s = SavedCpuState::new();
    let base = &s as *const SavedCpuState as usize;
    let at = |p: *const u64| p as usize - base;
    assert_eq!(OFF_REGS_RBX, at(&s.regs.rbx));
    assert_eq!(OFF_REGS_RBP, at(&s.regs.rbp));
    assert_eq!(OFF_REGS_R12, at(&s.regs.r12));
    assert_eq!(OFF_REGS_R13, at(&s.regs.r13));
    assert_eq!(OFF_REGS_R14, at(&s.regs.r14));
    assert_eq!(OFF_REGS_R15, at(&s.regs.r15));
    assert_eq!(OFF_REGS_RSP, at(&s.regs.rsp));
    assert_eq!(OFF_REGS_RFLAGS, at(&s.regs.rflags));
    assert_eq!(OFF_RESUME_RIP, at(&s.resume_rip));
    assert_eq!(OFF_RESUME_RSP, at(&s.resume_rsp));
    assert_eq!(OFF_MAGIC, at(&s.magic));
    assert_eq!(OFF_CR0, at(&s.cr0));
    assert_eq!(OFF_CR2, at(&s.cr2));
    assert_eq!(OFF_CR3, at(&s.cr3));
    assert_eq!(OFF_CR4, at(&s.cr4));
}

#[test]
fn a_fresh_record_is_not_armed() {
    let mut s = SavedCpuState::new();
    assert!(!s.armed(), "an unarmed record must not authorise a resume jump");
    s.magic = SUSPEND_MAGIC;
    assert!(s.armed());
    // One wrong bit is enough: this check exists precisely for the case where
    // firmware resumed somewhere unexpected.
    s.magic = SUSPEND_MAGIC ^ 1;
    assert!(!s.armed());
    s.magic = 0;
    assert!(!s.armed());
}

#[test]
fn only_low_page_aligned_addresses_can_carry_the_resume_stub() {
    assert!(resume_vector_placeable(0x9000));
    assert!(resume_vector_placeable(0x1000));
    assert!(resume_vector_placeable(REAL_MODE_LIMIT - RESUME_PAGE_BYTES));
    // Zero is "no vector published", never a valid one.
    assert!(!resume_vector_placeable(0));
    // Unaligned: firmware enters at a paragraph or page boundary.
    assert!(!resume_vector_placeable(0x9010));
    assert!(!resume_vector_placeable(0x8fff));
    // Above the first mebibyte real mode cannot address it at all.
    assert!(!resume_vector_placeable(REAL_MODE_LIMIT));
    assert!(!resume_vector_placeable(0x10_0000_0000));
    // A page that would run off the end of real-mode space.
    assert!(!resume_vector_placeable(REAL_MODE_LIMIT - RESUME_PAGE_BYTES + RESUME_PAGE_BYTES));
}

#[test]
fn the_real_mode_segment_is_the_address_paragraph() {
    assert_eq!(resume_vector_segment(0x9000), Some(0x900));
    assert_eq!(resume_vector_segment(0x1000), Some(0x100));
    assert_eq!(resume_vector_segment(0), None);
    assert_eq!(resume_vector_segment(0x10_0000), None);
}
