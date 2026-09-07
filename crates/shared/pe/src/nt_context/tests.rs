use super::*;

#[test]
fn the_record_offsets_are_the_published_layout() {
    // Field order is fixed by the ABI: P1Home..P6Home, ContextFlags, MxCsr,
    // the six segment selectors, EFlags, Dr0..Dr7, then the integer registers
    // in their canonical order, then FltSave at 0x100.
    assert_eq!((CTX_P1_HOME, CTX_P2_HOME), (0x00, 0x08));
    assert_eq!((CTX_FLAGS, CTX_MXCSR), (0x30, 0x34));
    assert_eq!((CTX_SEG_CS, CTX_SEG_DS, CTX_SEG_ES, CTX_SEG_FS, CTX_SEG_GS, CTX_SEG_SS), (0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42));
    assert_eq!(CTX_EFLAGS, 0x44);
    assert_eq!((CTX_RAX, CTX_RCX, CTX_RDX), (0x78, 0x80, 0x88));
    assert_eq!((CTX_RSP, CTX_RIP), (0x98, 0xf8));
    assert_eq!(CTX_FLT_SAVE, 0x100);
    assert_eq!(CTX_FLT_SAVE + FLT_SAVE_BYTES, 0x300);
    assert!(CONTEXT_BYTES >= CTX_FLT_SAVE + FLT_SAVE_BYTES);
}

#[test]
fn the_startup_context_names_the_entry_in_both_the_resume_point_and_the_first_argument() {
    let context = startup_context(0x1400_1234, 0xdead_beef, 0x7fff_0000);
    let at64 = |off: usize| u64::from_le_bytes(context[off..off + 8].try_into().unwrap());
    let at32 = |off: usize| u32::from_le_bytes(context[off..off + 4].try_into().unwrap());
    let at16 = |off: usize| u16::from_le_bytes(context[off..off + 2].try_into().unwrap());
    // The thunk reads the entry out of the first argument register and rewrites
    // it before resuming, so the record has to carry it in both places.
    assert_eq!(at64(CTX_RIP), 0x1400_1234);
    assert_eq!(at64(CTX_RCX), 0x1400_1234);
    assert_eq!(at64(CTX_RDX), 0xdead_beef);
    assert_eq!(at64(CTX_RSP), 0x7fff_0000);
    assert_eq!(at32(CTX_FLAGS), CONTEXT_FULL);
    assert_eq!(at32(CTX_MXCSR), MXCSR_INIT);
    assert_eq!(at32(CTX_FLT_SAVE as usize + FXSAVE_MXCSR), MXCSR_INIT);
    assert_eq!((at16(CTX_SEG_CS), at16(CTX_SEG_SS)), (USER_CS, USER_SS));
    // A resumed context with the reserved flag clear is not a valid flags word.
    assert_eq!(at32(CTX_EFLAGS) as u64 & EFLAGS_RESERVED, EFLAGS_RESERVED);
    // Nothing else is claimed: the debug registers stay zero and unadvertised.
    assert_eq!(at64(CTX_RAX), 0);
}
