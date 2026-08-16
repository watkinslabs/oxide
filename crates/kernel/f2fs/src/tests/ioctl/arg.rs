//! Reading the fixed argument structures.
//!
//! Layout is the ABI here, so every test builds the bytes at the offsets a
//! caller's compiler would place them at and requires the decode to land on
//! the same fields. A field read one word off decodes a plausible value from
//! its neighbour, which is exactly the failure these pin.

use alloc::vec;
use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::ioctl::arg::*;

fn zeroed(n: u32) -> Vec<u8> { vec![0u8; n as usize] }

fn put32(b: &mut [u8], at: usize, v: u32) { b[at..at + 4].copy_from_slice(&v.to_le_bytes()); }
fn put64(b: &mut [u8], at: usize, v: u64) { b[at..at + 8].copy_from_slice(&v.to_le_bytes()); }

// ---- key specifiers -------------------------------------------------------

#[test]
fn a_specifier_names_a_key_by_the_eight_bytes_the_caller_chose() {
    let mut b = zeroed(KEY_SPECIFIER_SIZE);
    put32(&mut b, SPEC_TYPE, KEY_SPEC_TYPE_DESCRIPTOR);
    b[SPEC_UNION..SPEC_UNION + 8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(key_spec(&b, 0), Ok(KeySpec::Descriptor([1, 2, 3, 4, 5, 6, 7, 8])));
}

#[test]
fn a_specifier_names_a_key_by_the_sixteen_bytes_derived_from_it() {
    let mut b = zeroed(KEY_SPECIFIER_SIZE);
    put32(&mut b, SPEC_TYPE, KEY_SPEC_TYPE_IDENTIFIER);
    for i in 0..16 { b[SPEC_UNION + i] = i as u8 + 0x40; }
    let mut want = [0u8; 16];
    for i in 0..16 { want[i] = i as u8 + 0x40; }
    assert_eq!(key_spec(&b, 0), Ok(KeySpec::Identifier(want)));
}

/// The two naming schemes must not collapse: a policy written under one names
/// nothing under the other, so the same bytes under a different type are a
/// different key.
#[test]
fn the_two_naming_schemes_stay_apart() {
    let mut d = zeroed(KEY_SPECIFIER_SIZE);
    put32(&mut d, SPEC_TYPE, KEY_SPEC_TYPE_DESCRIPTOR);
    let mut i = zeroed(KEY_SPECIFIER_SIZE);
    put32(&mut i, SPEC_TYPE, KEY_SPEC_TYPE_IDENTIFIER);
    assert_ne!(key_spec(&d, 0).unwrap(), key_spec(&i, 0).unwrap());
}

#[test]
fn a_specifier_with_its_reserved_word_set_is_refused() {
    let mut b = zeroed(KEY_SPECIFIER_SIZE);
    put32(&mut b, SPEC_TYPE, KEY_SPEC_TYPE_IDENTIFIER);
    put32(&mut b, SPEC_RESERVED, 1);
    assert_eq!(key_spec(&b, 0), Err(Errno::Einval));
}

#[test]
fn a_specifier_naming_no_scheme_is_refused() {
    let b = zeroed(KEY_SPECIFIER_SIZE);
    assert_eq!(key_spec(&b, 0), Err(Errno::Einval));
    let mut b = zeroed(KEY_SPECIFIER_SIZE);
    put32(&mut b, SPEC_TYPE, 99);
    assert_eq!(key_spec(&b, 0), Err(Errno::Einval));
}

#[test]
fn a_specifier_round_trips_through_the_reply_encoder() {
    for k in [KeySpec::Descriptor([9; 8]), KeySpec::Identifier([7; 16])] {
        let mut b = zeroed(KEY_SPECIFIER_SIZE);
        put_key_spec(&mut b, 0, &k).unwrap();
        assert_eq!(key_spec(&b, 0), Ok(k));
    }
}

// ---- adding a key ---------------------------------------------------------

fn add_key_arg(spec_type: u32, raw_size: u32) -> Vec<u8> {
    let mut b = zeroed(ADD_KEY_ARG_SIZE);
    put32(&mut b, ADD_KEY_SPECIFIER + SPEC_TYPE, spec_type);
    put32(&mut b, ADD_KEY_RAW_SIZE, raw_size);
    b
}

#[test]
fn adding_a_key_reads_its_size_from_the_field_after_the_specifier() {
    let b = add_key_arg(KEY_SPEC_TYPE_IDENTIFIER, 32);
    let k = add_key(&b, false).unwrap();
    assert_eq!(k.raw_size, 32);
    assert_eq!(k.key_id, 0);
    assert_eq!(k.flags, 0);
    assert!(matches!(k.spec, KeySpec::Identifier(_)));
}

/// A key named by something the caller chose could be any key, so the name a
/// policy refers to could be claimed by anyone. That refusal comes AFTER the
/// shape checks: a caller with a malformed reserved word learns that first.
#[test]
fn naming_a_key_by_a_chosen_descriptor_needs_the_capability() {
    let b = add_key_arg(KEY_SPEC_TYPE_DESCRIPTOR, 32);
    assert_eq!(add_key(&b, false).map(|k| k.raw_size), Err(Errno::Eacces));
    assert_eq!(add_key(&b, true).unwrap().raw_size, 32);
}

#[test]
fn the_reserved_words_are_reported_ahead_of_the_missing_capability() {
    let mut b = add_key_arg(KEY_SPEC_TYPE_DESCRIPTOR, 32);
    put32(&mut b, ADD_KEY_RESERVED, 1);
    assert_eq!(add_key(&b, false).map(|k| k.raw_size), Err(Errno::Einval));
}

/// The specifier itself is decoded FIRST, so a caller naming no scheme at all
/// is told its argument is malformed rather than that it lacks a capability.
#[test]
fn a_specifier_naming_no_scheme_is_reported_ahead_of_everything() {
    let mut b = add_key_arg(0, 32);
    put32(&mut b, ADD_KEY_RESERVED, 1);
    assert_eq!(add_key(&b, false).map(|k| k.raw_size), Err(Errno::Einval));
}

#[test]
fn a_key_shorter_or_longer_than_the_format_admits_is_refused() {
    let short = add_key_arg(KEY_SPEC_TYPE_IDENTIFIER,
                            crate::crypto::uapi::MIN_KEY_SIZE as u32 - 1);
    assert_eq!(add_key(&short, true).map(|k| k.raw_size), Err(Errno::Einval));
    let long = add_key_arg(KEY_SPEC_TYPE_IDENTIFIER, MAX_RAW_KEY as u32 + 1);
    assert_eq!(add_key(&long, true).map(|k| k.raw_size), Err(Errno::Einval));
}

/// A key taken from elsewhere and a key carried in the argument are two
/// answers to which key is being added, so carrying both is refused.
#[test]
fn naming_a_key_from_elsewhere_and_carrying_bytes_too_is_refused() {
    let mut b = add_key_arg(KEY_SPEC_TYPE_IDENTIFIER, 32);
    put32(&mut b, ADD_KEY_KEY_ID, 5);
    assert_eq!(add_key(&b, true).map(|k| k.raw_size), Err(Errno::Einval));
    // With no bytes carried, the same argument is well formed.
    let mut b = add_key_arg(KEY_SPEC_TYPE_IDENTIFIER, 0);
    put32(&mut b, ADD_KEY_KEY_ID, 5);
    assert_eq!(add_key(&b, true).unwrap().key_id, 5);
}

#[test]
fn an_undefined_add_key_flag_is_refused_and_the_defined_one_needs_the_newer_scheme() {
    let mut b = add_key_arg(KEY_SPEC_TYPE_IDENTIFIER, 32);
    put32(&mut b, ADD_KEY_FLAGS, 0x8000);
    assert_eq!(add_key(&b, true).map(|k| k.flags), Err(Errno::Einval));
    let mut b = add_key_arg(KEY_SPEC_TYPE_DESCRIPTOR, 32);
    put32(&mut b, ADD_KEY_FLAGS, ADD_KEY_FLAG_HW_WRAPPED);
    assert_eq!(add_key(&b, true).map(|k| k.flags), Err(Errno::Einval));
    let mut b = add_key_arg(KEY_SPEC_TYPE_IDENTIFIER, 32);
    put32(&mut b, ADD_KEY_FLAGS, ADD_KEY_FLAG_HW_WRAPPED);
    assert_eq!(add_key(&b, true).unwrap().flags, ADD_KEY_FLAG_HW_WRAPPED);
}

// ---- removing a key and asking after one ---------------------------------

#[test]
fn removing_a_key_applies_the_same_descriptor_rule_as_adding_one() {
    let mut b = zeroed(REMOVE_KEY_ARG_SIZE);
    put32(&mut b, REMOVE_KEY_SPECIFIER + SPEC_TYPE, KEY_SPEC_TYPE_DESCRIPTOR);
    assert_eq!(remove_key(&b, false), Err(Errno::Eacces));
    assert!(remove_key(&b, true).is_ok());
}

/// Asking after a key reveals nothing a caller could not learn by trying to
/// use one, so it needs no capability even for the chosen-name scheme.
#[test]
fn asking_after_a_key_needs_no_capability() {
    let mut b = zeroed(KEY_STATUS_ARG_SIZE);
    put32(&mut b, KEY_STATUS_SPECIFIER + SPEC_TYPE, KEY_SPEC_TYPE_DESCRIPTOR);
    assert!(key_status(&b).is_ok());
}

/// The status argument's caller-supplied half ends before the fields the
/// kernel fills in; a reserved-word check reaching into the output half would
/// refuse every second call after the first filled them.
#[test]
fn the_status_reserved_check_stops_before_the_output_fields() {
    let mut b = zeroed(KEY_STATUS_ARG_SIZE);
    put32(&mut b, KEY_STATUS_SPECIFIER + SPEC_TYPE, KEY_SPEC_TYPE_IDENTIFIER);
    put32(&mut b, KEY_STATUS_STATUS, KEY_STATUS_PRESENT);
    put32(&mut b, KEY_STATUS_USER_COUNT, 3);
    assert!(key_status(&b).is_ok());
    // …but a set word in the caller's own half is refused.
    put32(&mut b, KEY_STATUS_RESERVED, 1);
    assert_eq!(key_status(&b), Err(Errno::Einval));
}

// ---- the extended file-attribute record ----------------------------------

#[test]
fn the_attribute_record_round_trips() {
    let fa = FsxAttr { xflags: FS_XFLAG_APPEND, extsize: 7, nextents: 9, projid: 11,
                       cowextsize: 13 };
    assert_eq!(fsxattr(&put_fsxattr(&fa).unwrap()), Ok(fa));
}

#[test]
fn an_attribute_record_with_its_pad_set_is_refused() {
    let mut b = put_fsxattr(&FsxAttr::default()).unwrap();
    b[FSX_PAD] = 1;
    assert_eq!(fsxattr(&b), Err(Errno::Einval));
}

// ---- turning verity on ----------------------------------------------------

fn enable_arg() -> Vec<u8> {
    let mut b = zeroed(VERITY_ENABLE_ARG_SIZE);
    put32(&mut b, VE_VERSION, VERITY_ENABLE_VERSION);
    put32(&mut b, VE_HASH_ALGORITHM, 1);
    put32(&mut b, VE_BLOCK_SIZE, 4096);
    b
}

#[test]
fn a_well_formed_enable_argument_decodes() {
    let h = verity_enable_head(&enable_arg()).unwrap();
    assert_eq!(h.hash_algorithm, 1);
    assert_eq!(h.block_size, 4096);
    assert_eq!(h.salt_size, 0);
    assert_eq!(h.sig_size, 0);
}

#[test]
fn an_enable_argument_of_another_version_is_refused() {
    let mut b = enable_arg();
    put32(&mut b, VE_VERSION, 2);
    assert_eq!(verity_enable_head(&b).map(|h| h.block_size), Err(Errno::Einval));
}

#[test]
fn an_enable_argument_with_a_reserved_word_set_is_refused() {
    let mut b = enable_arg();
    put32(&mut b, VE_RESERVED1, 1);
    assert_eq!(verity_enable_head(&b).map(|h| h.block_size), Err(Errno::Einval));
    let mut b = enable_arg();
    put64(&mut b, VE_RESERVED2 + 80, 1);
    assert_eq!(verity_enable_head(&b).map(|h| h.block_size), Err(Errno::Einval));
}

/// The tree's block size is a shift, so a size that is not a power of two
/// describes a tree nothing can index.
#[test]
fn a_tree_block_size_that_is_not_a_power_of_two_is_refused() {
    let mut b = enable_arg();
    put32(&mut b, VE_BLOCK_SIZE, 3000);
    assert_eq!(verity_enable_head(&b).map(|h| h.block_size), Err(Errno::Einval));
}

/// The two length ceilings report a message-size error, not a shape error:
/// the request is well formed and merely too big.
#[test]
fn a_salt_or_signature_past_its_ceiling_reports_a_size_error() {
    let mut b = enable_arg();
    put32(&mut b, VE_SALT_SIZE, VERITY_MAX_SALT as u32 + 1);
    put64(&mut b, VE_SALT_PTR, 0x1000);
    assert_eq!(verity_enable_head(&b).map(|h| h.salt_size), Err(Errno::Emsgsize));
    let mut b = enable_arg();
    put32(&mut b, VE_SIG_SIZE, VERITY_MAX_SIGNATURE as u32 + 1);
    put64(&mut b, VE_SIG_PTR, 0x1000);
    assert_eq!(verity_enable_head(&b).map(|h| h.sig_size), Err(Errno::Emsgsize));
}

/// The unindexable geometry is reported ahead of the oversized salt: one
/// describes a tree that cannot exist, the other a request merely too large.
#[test]
fn the_unindexable_block_size_is_reported_ahead_of_an_oversized_salt() {
    let mut b = enable_arg();
    put32(&mut b, VE_BLOCK_SIZE, 3000);
    put32(&mut b, VE_SALT_SIZE, VERITY_MAX_SALT as u32 + 1);
    assert_eq!(verity_enable_head(&b).map(|h| h.salt_size), Err(Errno::Einval));
}

// ---- reading verity metadata ---------------------------------------------

fn read_arg(kind: u64, offset: u64, length: u64) -> Vec<u8> {
    let mut b = zeroed(VERITY_READ_METADATA_SIZE);
    put64(&mut b, VRM_TYPE, kind);
    put64(&mut b, VRM_OFFSET, offset);
    put64(&mut b, VRM_LENGTH, length);
    put64(&mut b, VRM_BUF_PTR, 0x2000);
    b
}

#[test]
fn each_defined_metadata_kind_decodes() {
    for k in [VERITY_METADATA_TYPE_MERKLE_TREE, VERITY_METADATA_TYPE_DESCRIPTOR,
              VERITY_METADATA_TYPE_SIGNATURE] {
        assert_eq!(read_metadata(&read_arg(k, 0, 64)).unwrap().kind, k);
    }
}

#[test]
fn an_undefined_metadata_kind_is_refused() {
    assert_eq!(read_metadata(&read_arg(99, 0, 64)).map(|m| m.kind), Err(Errno::Einval));
}

/// A length past what the result can report is SHORTENED, not refused: a
/// caller asking for everything gets what fits and asks again.
#[test]
fn a_length_past_what_the_result_can_report_is_shortened() {
    let m = read_metadata(&read_arg(VERITY_METADATA_TYPE_DESCRIPTOR, 0, u64::MAX - 1))
        .unwrap();
    assert_eq!(m.length, i32::MAX as u64);
}

/// A span that wraps names memory that does not exist, and is checked on the
/// caller's OWN numbers — before the length is clamped, or an overflowing
/// request would look like an ordinary long one.
#[test]
fn a_span_that_wraps_is_refused_rather_than_clamped() {
    let b = read_arg(VERITY_METADATA_TYPE_DESCRIPTOR, u64::MAX - 4, 16);
    assert_eq!(read_metadata(&b).map(|m| m.length), Err(Errno::Einval));
}

#[test]
fn a_read_argument_with_its_reserved_word_set_is_refused() {
    let mut b = read_arg(VERITY_METADATA_TYPE_DESCRIPTOR, 0, 64);
    put64(&mut b, VRM_RESERVED, 1);
    assert_eq!(read_metadata(&b).map(|m| m.kind), Err(Errno::Einval));
}

// ---- short payloads -------------------------------------------------------

/// A payload the copy layer could not fill reads as a faulted access, which
/// is what the caller that supplied it would have got.
#[test]
fn a_payload_shorter_than_its_structure_reports_a_fault() {
    assert_eq!(u32_at(&[0u8; 2], 0), Err(Errno::Efault));
    assert_eq!(u64_at(&[0u8; 4], 0), Err(Errno::Efault));
    assert_eq!(key_spec(&[0u8; 2], 0), Err(Errno::Efault));
    // A buffer long enough to hold the type but not the name it selects still
    // faults, rather than decoding a name out of bytes that are not there.
    let mut short = vec![0u8; SPEC_UNION + 4];
    put32(&mut short, SPEC_TYPE, KEY_SPEC_TYPE_IDENTIFIER);
    assert_eq!(key_spec(&short, 0), Err(Errno::Efault));
    assert_eq!(fsxattr(&[0u8; 8]), Err(Errno::Efault));
    assert_eq!(read_metadata(&[0u8; 8]).map(|m| m.kind), Err(Errno::Efault));
}
