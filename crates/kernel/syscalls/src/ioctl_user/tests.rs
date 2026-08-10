use super::copy::*;
use super::layout::*;

use syscall::errno::Errno;

const EINVAL: i64 = -(Errno::Einval.as_i32() as i64);
const ENOMEM: i64 = -(Errno::Enomem.as_i32() as i64);

fn addr_of(b: &[u8]) -> u64 { b.as_ptr() as u64 }

#[test]
fn a_fixed_size_fetch_and_store_round_trips() {
    let buf = [0u8; 16];
    let a = addr_of(&buf);
    assert_eq!(put_u32(a, 0xdead_beef), Ok(()));
    assert_eq!(put_u64(a + 8, 0x0102_0304_0506_0708), Ok(()));
    assert_eq!(get_u32(a), Ok(0xdead_beef));
    assert_eq!(get_bytes::<8>(a + 8), Ok(0x0102_0304_0506_0708u64.to_ne_bytes()));
    assert_eq!(get_bytes::<4>(a), Ok(0xdead_beefu32.to_ne_bytes()));
    assert_eq!(get_u8(a), Ok(0xdead_beefu32.to_ne_bytes()[0]));
}

/// Every TIOCLINUX field but the subcode is misaligned by construction (the
/// parameter block starts one byte in), so the accessors must not assume
/// natural alignment the way a typed dereference does.
#[test]
fn an_unaligned_field_round_trips() {
    let buf = [0u8; 16];
    let a = addr_of(&buf);
    assert_eq!(put_u16(a + 1, 0x1234), Ok(()));
    assert_eq!(put_i64(a + 3, -2), Ok(()));
    assert_eq!(get_u16(a + 1), Ok(0x1234));
    assert_eq!(get_bytes::<8>(a + 3), Ok((-2i64).to_ne_bytes()));
}

#[test]
fn a_null_address_faults_in_both_directions() {
    assert_eq!(get_u32(0), Err(EFAULT));
    assert_eq!(put_u32(0, 1), Err(EFAULT));
    assert_eq!(get_bytes::<8>(0), Err(EFAULT));
    let mut dst = [0u8; 4];
    assert_eq!(get_into(0, &mut dst), Err(EFAULT));
    assert_eq!(put_bytes(0, &dst), Err(EFAULT));
}

/// The whole point of routing through the fault-recoverable usercopy: an
/// address outside the user window answers EFAULT instead of dereferencing.
#[test]
fn an_address_outside_the_user_window_faults() {
    assert_eq!(get_u32(hal::USER_VA_END), Err(EFAULT));
    assert_eq!(put_u32(hal::USER_VA_END, 1), Err(EFAULT));
    // A span that STARTS inside and runs past the end is rejected whole.
    assert_eq!(get_bytes::<8>(hal::USER_VA_END - 4), Err(EFAULT));
    assert_eq!(put_u64(hal::USER_VA_END - 4, 1), Err(EFAULT));
    // And one whose length overflows the address arithmetic.
    assert_eq!(get_bytes::<8>(u64::MAX - 1), Err(EFAULT));
}

#[test]
fn a_faulting_store_leaves_the_source_untouched() {
    let src = [0xaau8; 8];
    assert_eq!(put_bytes(u64::MAX - 1, &src), Err(EFAULT));
    assert_eq!(src, [0xaau8; 8]);
}

/// The parameter block the reference hands each TIOCLINUX subfunction: byte
/// commands read one byte in, word commands four bytes in. Reading a word
/// command at the byte offset (or the selection rectangle at offset 2) puts
/// every field on the wrong address.
#[test]
fn tioclinux_parameter_blocks_sit_where_the_abi_puts_them() {
    assert_eq!(TIOCL_SUBCODE, 0);
    assert_eq!(TIOCL_PARAM, 1);
    assert_eq!(TIOCL_PARAM32, 4);
    let fields: [u64; 5] = core::array::from_fn(|i| tiocl_sel_field(i as u64));
    assert_eq!(fields, [1, 3, 5, 7, 9]);
}

#[test]
fn a_fiemap_extent_span_is_counted_and_bounded() {
    assert_eq!(fiemap_extent_span(0), Ok(0));
    assert_eq!(fiemap_extent_span(1), Ok(FIEMAP_EXTENT_BYTES));
    let max = u32::MAX / FIEMAP_EXTENT_BYTES as u32;
    assert_eq!(fiemap_extent_span(max), Ok(max as u64 * FIEMAP_EXTENT_BYTES));
    assert_eq!(fiemap_extent_span(max + 1), Err(EINVAL));
}

#[test]
fn a_dedupe_payload_past_one_page_is_enomem() {
    assert_eq!(dedupe_payload_bytes(0), Ok(24));
    assert_eq!(dedupe_payload_bytes(1), Ok(24 + 32));
    assert_eq!(dedupe_payload_bytes(127), Ok(4088));
    assert_eq!(dedupe_payload_bytes(128), Err(ENOMEM));
    assert_eq!(dedupe_payload_bytes(u16::MAX), Err(ENOMEM));
}

#[test]
fn a_font_glyph_span_rejects_empty_and_oversized_counts() {
    assert_eq!(font_glyph_bytes(0), Err(EINVAL));
    assert_eq!(font_glyph_bytes(1), Ok(FONT_GLYPH_STRIDE));
    assert_eq!(font_glyph_bytes(FONT_MAX_GLYPHS), Ok(FONT_MAX_GLYPHS as usize * FONT_GLYPH_STRIDE));
    assert_eq!(font_glyph_bytes(FONT_MAX_GLYPHS + 1), Err(EINVAL));
}

#[test]
fn a_unimap_span_is_four_bytes_an_entry_and_bounded() {
    assert_eq!(unimap_span(0), Ok(0));
    assert_eq!(unimap_span(3), Ok(3 * UNIMAP_PAIR_BYTES));
    assert_eq!(unimap_span(UNIMAP_MAX_ENTRIES), Ok(UNIMAP_MAX_ENTRIES as u64 * UNIMAP_PAIR_BYTES));
    assert_eq!(unimap_span(UNIMAP_MAX_ENTRIES + 1), Err(EINVAL));
}
