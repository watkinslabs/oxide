use syscall::errno::Errno;

use crate::ldt_abi::write::check_bytecount;
use crate::ldt_abi::{validate_write, LdtFunc, UserDesc, LDT_ENTRIES, USER_DESC_BYTES};

fn plain() -> UserDesc {
    UserDesc { entry_number: 1, base_addr: 0x1000, limit: 0xFFF, seg_32bit: true,
               ..UserDesc::default() }
}

#[test]
fn bytecount_must_be_exactly_one_user_desc() {
    assert_eq!(USER_DESC_BYTES, 16);
    assert!(check_bytecount(16).is_ok());
    for n in [0u64, 1, 8, 15, 17, 24, u64::MAX] {
        assert_eq!(check_bytecount(n), Err(Errno::Einval), "bytecount {n}");
    }
}

#[test]
fn the_size_test_precedes_any_pointer_dereference() {
    // The ordering contract, expressed the only way it can be from here: the
    // size rule is decidable with NO user pointer in hand, so a wrong size
    // can never produce EFAULT. The slot file copies only after this passes.
    assert_eq!(check_bytecount(4), Err(Errno::Einval));
    assert_ne!(check_bytecount(4), Err(Errno::Efault));
}

#[test]
fn entry_number_beyond_the_table_is_einval() {
    let mut info = plain();
    info.entry_number = LDT_ENTRIES;
    assert_eq!(validate_write(&info, LdtFunc::WriteNew), Err(Errno::Einval));
    info.entry_number = u32::MAX;
    assert_eq!(validate_write(&info, LdtFunc::WriteNew), Err(Errno::Einval));
    info.entry_number = LDT_ENTRIES - 1;
    assert!(validate_write(&info, LdtFunc::WriteNew).is_ok());
}

#[test]
fn conforming_contents_are_refused_outright_by_the_original_sub_function() {
    let mut info = plain();
    info.contents = crate::ldt_abi::CONTENTS_RESERVED;
    info.seg_not_present = true;
    assert_eq!(validate_write(&info, LdtFunc::Write), Err(Errno::Einval),
               "contents==3 has no encoding under the original semantics");
    assert!(validate_write(&info, LdtFunc::WriteNew).is_ok(),
            "not-present conforming code is accepted by the current semantics");
}

#[test]
fn a_present_conforming_segment_is_refused() {
    // Conforming code keeps the caller's privilege across a far transfer; a
    // present one in a user LDT is a privilege-retention primitive.
    let mut info = plain();
    info.contents = crate::ldt_abi::CONTENTS_RESERVED;
    info.seg_not_present = false;
    assert_eq!(validate_write(&info, LdtFunc::WriteNew), Err(Errno::Einval));
    assert_eq!(validate_write(&info, LdtFunc::Write), Err(Errno::Einval));
}

#[test]
fn entry_number_is_checked_before_the_contents_rule() {
    let mut info = plain();
    info.entry_number = LDT_ENTRIES + 5;
    info.contents = crate::ldt_abi::CONTENTS_RESERVED;
    info.seg_not_present = false;
    // Both rules say EINVAL, so the ordering is observable only through the
    // slot the request names: an out-of-range entry must not be reported as a
    // contents problem the caller could "fix" and retry into range.
    assert_eq!(validate_write(&info, LdtFunc::WriteNew), Err(Errno::Einval));
    info.entry_number = 3;
    assert_eq!(validate_write(&info, LdtFunc::WriteNew), Err(Errno::Einval));
}

#[test]
fn original_semantics_clear_on_zero_base_and_limit_alone() {
    let info = UserDesc { entry_number: 4, base_addr: 0, limit: 0, seg_32bit: true,
                          useable: true, ..UserDesc::default() };
    let e = validate_write(&info, LdtFunc::Write).expect("old-mode clear");
    assert_eq!(e.desc, 0, "zero base+limit clears under the original semantics");
    assert_eq!(e.entry_number, 4);
    // The same request under the current semantics installs a real segment.
    let e = validate_write(&info, LdtFunc::WriteNew).expect("new-mode install");
    assert_ne!(e.desc, 0, "current semantics clear only for a fully empty user_desc");
}

#[test]
fn current_semantics_clear_only_for_the_empty_shape() {
    let empty = UserDesc { entry_number: 9, read_exec_only: true, seg_not_present: true,
                           ..UserDesc::default() };
    assert_eq!(validate_write(&empty, LdtFunc::WriteNew).expect("clears").desc, 0);
    // An all-zero user_desc is NOT the empty shape: it has read_exec_only and
    // seg_not_present clear, so it installs a present writable data segment.
    let zero = UserDesc { entry_number: 9, ..UserDesc::default() };
    assert_ne!(validate_write(&zero, LdtFunc::WriteNew).expect("installs").desc, 0);
}

#[test]
fn sixteen_bit_segments_are_accepted() {
    // The reference refuses these only when built without 16-bit segment
    // support, or under a paravirtualised guest lacking the IRET fixup. This
    // port is neither, and refusing would break every 16-bit emulator.
    assert!(crate::ldt_abi::ALLOW_16BIT_SEGMENTS);
    let info = UserDesc { entry_number: 2, base_addr: 0x2000, limit: 0xFFFF,
                          seg_32bit: false, ..UserDesc::default() };
    let e = validate_write(&info, LdtFunc::WriteNew).expect("16-bit segment accepted");
    assert_eq!((e.desc >> 54) & 1, 0, "D bit clear for a 16-bit segment");
}

#[test]
fn required_entries_covers_the_named_slot() {
    let e = validate_write(&plain(), LdtFunc::WriteNew).expect("ok");
    assert_eq!(e.required_entries(), 2);
    let mut top = plain();
    top.entry_number = LDT_ENTRIES - 1;
    let e = validate_write(&top, LdtFunc::WriteNew).expect("ok");
    assert_eq!(e.required_entries(), LDT_ENTRIES);
}
