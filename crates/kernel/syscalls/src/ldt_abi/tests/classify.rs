use syscall::errno::Errno;

use crate::ldt_abi::{classify, unsupported_func_errno, LdtFunc};

#[test]
fn the_four_defined_sub_functions_resolve() {
    assert_eq!(classify(0), Some(LdtFunc::Read));
    assert_eq!(classify(1), Some(LdtFunc::Write));
    assert_eq!(classify(2), Some(LdtFunc::ReadDefault));
    assert_eq!(classify(0x11), Some(LdtFunc::WriteNew));
}

#[test]
fn every_other_func_is_enosys_not_einval() {
    // A caller probing for a sub-function must be able to tell "no such
    // operation" from "bad arguments" — the two are answered differently and
    // only one of them is worth retrying with different arguments.
    assert_eq!(unsupported_func_errno(), -(Errno::Enosys.as_i32() as i64));
    assert_ne!(unsupported_func_errno(), -(Errno::Einval.as_i32() as i64));
    for func in [-1i32, 3, 4, 0x10, 0x12, 0x7FFF_FFFF, i32::MIN] {
        assert_eq!(classify(func), None, "func {func} must not resolve");
    }
}

#[test]
fn sub_function_one_carries_the_original_write_semantics() {
    // The numerically larger code is the NEWER contract: 1 is the original
    // write and 0x11 the current one. Getting this backwards silently flips
    // the clear-entry rule and the AVL bit for every caller.
    assert!(LdtFunc::Write.oldmode());
    assert!(!LdtFunc::WriteNew.oldmode());
    assert!(!LdtFunc::Read.oldmode());
    assert!(!LdtFunc::ReadDefault.oldmode());
}

#[test]
fn func_is_read_as_a_signed_int() {
    // The argument arrives in a 64-bit register but is an `int`. A caller
    // passing a negative func through a register with a set high half must
    // still land in the ENOSYS arm rather than aliasing onto a valid code.
    let raw: u64 = 0xFFFF_FFFF_0000_0001;
    assert_eq!(classify(raw as u32 as i32), Some(LdtFunc::Write));
    let raw: u64 = 0x0000_0001_0000_0000;
    assert_eq!(classify(raw as u32 as i32), Some(LdtFunc::Read));
}
