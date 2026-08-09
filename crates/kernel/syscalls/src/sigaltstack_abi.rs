// `stack_t` wire layout for `sigaltstack(2)`, and the decode of one.
//
// Ungated on purpose. The syscall slot is `#[cfg(target_os = "oxide-kernel")]`,
// so a test written beside it there compiles out entirely and reports nothing —
// the layout would be provable only by a kernel build. The decision here (which
// bytes are which field) is exactly the part worth a test, so it lives where a
// test can fail.

use sched::sigaltstack::AltStack;

/// `sizeof(stack_t)`: `void *ss_sp`, `int ss_flags` with its padding, and
/// `size_t ss_size`.
pub(crate) const STACK_T_BYTES: usize = 24;
/// Byte offset of `ss_flags`.
pub(crate) const SS_FLAGS_OFF: usize = 8;
/// Byte offset of `ss_size`.
pub(crate) const SS_SIZE_OFF: usize = 16;

/// Decode one user `stack_t` from its wire bytes.
///
/// `ss_flags` is a 32-bit `int` followed by four bytes of padding on both
/// targets; reading it as a word would fold that padding into the value.
/// # C: O(1)
pub(crate) fn decode_stack_t(raw: &[u8; STACK_T_BYTES]) -> AltStack {
    let word = |o: usize| u64::from_ne_bytes(raw[o..o + 8].try_into().expect("8 of 24"));
    AltStack {
        sp:    word(0),
        flags: i32::from_ne_bytes(raw[SS_FLAGS_OFF..SS_FLAGS_OFF + 4].try_into().expect("4 of 24")),
        size:  word(SS_SIZE_OFF),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Offsets spelled as LITERALS, never as the constants under test: a
    /// fixture built from its own subject moves with it, so an offset that
    /// drifted would still "pass".
    fn wire(sp: u64, flags: i32, size: u64) -> [u8; 24] {
        let mut raw = [0u8; 24];
        raw[0..8].copy_from_slice(&sp.to_ne_bytes());
        raw[8..12].copy_from_slice(&flags.to_ne_bytes());
        raw[16..24].copy_from_slice(&size.to_ne_bytes());
        raw
    }

    #[test]
    fn each_field_comes_from_its_own_offset() {
        let a = decode_stack_t(&wire(0xDEAD_0000, 1, 0x4000));
        assert_eq!((a.sp, a.flags, a.size), (0xDEAD_0000, 1, 0x4000));
    }

    /// Every field must come from ITS offset and no other. Written as three
    /// distinct byte patterns rather than a padding assertion: on a
    /// little-endian target — which both of ours are — reading `ss_flags` as a
    /// word and truncating gives the same answer, so a padding test cannot
    /// fail and proves nothing. Moving an offset is the mutation that can.
    #[test]
    fn a_field_read_from_the_wrong_offset_is_caught() {
        let a = decode_stack_t(&wire(0x1111_1111_1111_1111, 0x2222_2222, 0x3333_3333_3333_3333));
        assert_eq!(a.sp, 0x1111_1111_1111_1111, "ss_sp is offset 0");
        assert_eq!(a.flags, 0x2222_2222, "ss_flags is offset 8, not 0 or 16");
        assert_eq!(a.size, 0x3333_3333_3333_3333, "ss_size is offset 16");
    }

    /// A negative `ss_flags` survives the decode: rejecting an unknown flag is
    /// the caller's rule, and a reader that clamped here would hide the EINVAL
    /// the caller owes.
    #[test]
    fn a_negative_flags_word_is_preserved() {
        assert_eq!(decode_stack_t(&wire(0, -1, 0)).flags, -1);
    }

    #[test]
    fn the_layout_constants_are_the_abi_ones() {
        assert_eq!((STACK_T_BYTES, SS_FLAGS_OFF, SS_SIZE_OFF), (24, 8, 16));
    }
}
