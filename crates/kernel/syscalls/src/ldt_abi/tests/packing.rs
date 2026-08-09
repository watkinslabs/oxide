// Byte-exact descriptor packing. These are the tests that catch a bit-layout
// mistake: a wrong DPL, a dropped present bit or a shifted type nibble all
// still produce a plausible-looking u64, and nothing downstream would notice
// until userspace held a segment it should not have.

use crate::ldt_abi::{desc, fill_ldt, LdtFunc, UserDesc};

/// A writable 32-bit data segment with every field distinct, so a swapped
/// base/limit half or a mis-shifted nibble moves the answer.
fn data_segment() -> UserDesc {
    UserDesc {
        entry_number: 7,
        base_addr: 0x1234_5678,
        limit: 0x000A_BCDE,
        seg_32bit: true,
        contents: crate::ldt_abi::CONTENTS_DATA,
        read_exec_only: false,
        limit_in_pages: true,
        seg_not_present: false,
        useable: true,
        lm: false,
    }
}

#[test]
fn data_segment_packs_to_the_exact_eight_bytes() {
    // limit0=0xBCDE base0=0x5678 base1=0x34
    // access = type(3: accessed|writable|data) | S | DPL3 | P    = 0xF3
    // flags  = limit1(0xA) | AVL | D | G                          = 0xDA
    // base2  = 0x12
    let d = fill_ldt(&data_segment(), false);
    assert_eq!(d.to_le_bytes(), [0xDE, 0xBC, 0x78, 0x56, 0x34, 0xF3, 0xDA, 0x12]);
    assert_eq!(d, 0x12DA_F334_5678_BCDE);
}

#[test]
fn execute_only_code_segment_packs_to_the_exact_eight_bytes() {
    // The classic flat 32-bit code segment, execute-only: type nibble 9
    // (accessed | code), granular, D=1, base 0, limit 0xFFFFF.
    let info = UserDesc {
        entry_number: 0,
        base_addr: 0,
        limit: 0x000F_FFFF,
        seg_32bit: true,
        contents: crate::ldt_abi::CONTENTS_CODE,
        read_exec_only: true,
        limit_in_pages: true,
        seg_not_present: false,
        useable: false,
        lm: false,
    };
    let d = fill_ldt(&info, false);
    assert_eq!(d.to_le_bytes(), [0xFF, 0xFF, 0x00, 0x00, 0x00, 0xF9, 0xCF, 0x00]);
    assert_eq!(d, 0x00CF_F900_0000_FFFF);
}

#[test]
fn readable_code_segment_sets_the_read_bit_not_clears_it() {
    // `read_exec_only` is INVERTED into the descriptor's write/read bit. A
    // straight copy would produce 0xF9 here and 0xFB above — both plausible,
    // both wrong, and the mistake grants or removes read access silently.
    let mut info = UserDesc { read_exec_only: false, ..UserDesc::default() };
    info.contents = crate::ldt_abi::CONTENTS_CODE;
    info.seg_32bit = true;
    info.limit = 0x000F_FFFF;
    info.limit_in_pages = true;
    let d = fill_ldt(&info, false);
    assert_eq!((d >> 40) & 0xFF, 0xFB, "accessed | readable | code, S, DPL3, P");
}

#[test]
fn expand_down_stack_contents_lands_in_the_type_nibble() {
    let mut info = data_segment();
    info.contents = crate::ldt_abi::CONTENTS_STACK;
    let d = fill_ldt(&info, false);
    // type = accessed(1) | writable(2) | contents<<2 (4) = 7.
    assert_eq!((d >> 40) & 0xF, 0x7);
}

#[test]
fn every_entry_is_dpl_three_and_non_system() {
    for contents in 0..4u32 {
        let mut info = data_segment();
        info.contents = contents;
        info.seg_not_present = contents == crate::ldt_abi::CONTENTS_RESERVED;
        let d = fill_ldt(&info, false);
        assert_eq!((d >> 45) & 0x3, 3, "DPL must be 3 for contents={contents}");
        assert_eq!((d >> 44) & 0x1, 1, "S must be 1 (never a system descriptor)");
    }
}

#[test]
fn the_long_mode_bit_is_never_set_from_user_input() {
    let mut info = data_segment();
    info.lm = true;
    info.contents = crate::ldt_abi::CONTENTS_CODE;
    assert_eq!((fill_ldt(&info, false) >> 53) & 1, 0, "L bit must stay clear");
    assert_eq!((fill_ldt(&info, true) >> 53) & 1, 0, "L bit must stay clear (oldmode)");
}

#[test]
fn seg_not_present_clears_the_present_bit() {
    let mut info = data_segment();
    info.seg_not_present = true;
    assert_eq!((fill_ldt(&info, false) >> 47) & 1, 0);
    info.seg_not_present = false;
    assert_eq!((fill_ldt(&info, false) >> 47) & 1, 1);
}

#[test]
fn oldmode_forces_the_avl_bit_to_zero() {
    let info = data_segment();
    assert_eq!((fill_ldt(&info, false) >> 52) & 1, 1, "useable reaches AVL in new mode");
    assert_eq!((fill_ldt(&info, true) >> 52) & 1, 0, "oldmode has no useable bit");
}

#[test]
fn the_accessed_bit_is_always_preset() {
    // Preset so the CPU never needs to write to the table.
    for contents in [0u32, 1, 2] {
        let mut info = data_segment();
        info.contents = contents;
        assert_eq!(fill_ldt(&info, false) & (1 << 40), 1 << 40);
    }
}

#[test]
fn base_and_limit_halves_do_not_bleed_into_each_other() {
    let info = UserDesc {
        base_addr: 0xFFFF_FFFF, limit: 0x000F_FFFF, seg_32bit: true, limit_in_pages: true,
        ..UserDesc::default()
    };
    let d = fill_ldt(&info, false);
    assert_eq!(d & 0xFFFF, 0xFFFF, "limit[15:0]");
    assert_eq!((d >> 16) & 0xFFFF, 0xFFFF, "base[15:0]");
    assert_eq!((d >> 32) & 0xFF, 0xFF, "base[23:16]");
    assert_eq!((d >> 48) & 0xF, 0xF, "limit[19:16]");
    assert_eq!((d >> 56) & 0xFF, 0xFF, "base[31:24]");
    // A limit wider than 20 bits must not reach the descriptor at all.
    let wide = UserDesc { limit: 0xFFFF_FFFF, ..UserDesc::default() };
    let d = fill_ldt(&wide, false);
    assert_eq!(d & 0xFFFF, 0xFFFF);
    assert_eq!((d >> 48) & 0xF, 0xF);
}

#[test]
fn a_cleared_entry_is_eight_zero_bytes() {
    let empty = UserDesc {
        read_exec_only: true, seg_not_present: true, ..UserDesc::default()
    };
    assert!(desc::ldt_empty(&empty));
    let e = crate::ldt_abi::validate_write(&empty, LdtFunc::WriteNew).expect("empty clears");
    assert_eq!(e.desc, 0);
    assert_eq!(e.desc.to_le_bytes(), [0u8; 8]);
}

#[test]
fn desc_bytes_matches_the_uapi_entry_size() {
    assert_eq!(desc::DESC_BYTES as u32, crate::ldt_abi::LDT_ENTRY_SIZE);
    assert_eq!(desc::DESC_BYTES, core::mem::size_of::<u64>());
}
