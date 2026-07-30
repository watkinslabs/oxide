use alloc::vec::Vec;
use super::super::format::*;
use super::parse;
use syscall::errno::Errno;

const TEST_HEADER_LEN: u32 = LEGACY_HEADER_LEN as u32;
const INFO_KIND_FLAG_TEST: u32 = INFO_KIND_FLAG;

fn push32(v: &mut Vec<u8>, n: u32) { v.extend_from_slice(&n.to_ne_bytes()); }

fn ty(v: &mut Vec<u8>, name: u32, kind: Kind, vlen: u32, kflag: bool, value: u32) {
    push32(v, name);
    let info = vlen | (kind as u32) << INFO_KIND_SHIFT
        | if kflag { INFO_KIND_FLAG_TEST } else { 0 };
    push32(v, info);
    push32(v, value);
}

fn blob(types: &[u8], strings: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&MAGIC.to_ne_bytes());
    v.push(VERSION);
    v.push(FLAGS_NONE);
    push32(&mut v, TEST_HEADER_LEN);
    push32(&mut v, 0);
    push32(&mut v, types.len() as u32);
    push32(&mut v, types.len() as u32);
    push32(&mut v, strings.len() as u32);
    v.extend_from_slice(types);
    v.extend_from_slice(strings);
    v
}

fn blob_with_layout(types: &[u8], strings: &[u8], layout: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&MAGIC.to_ne_bytes());
    v.push(VERSION);
    v.push(FLAGS_NONE);
    push32(&mut v, HEADER_LEN as u32);
    push32(&mut v, 0);
    push32(&mut v, types.len() as u32);
    push32(&mut v, (types.len() + layout.len()) as u32);
    push32(&mut v, strings.len() as u32);
    push32(&mut v, types.len() as u32);
    push32(&mut v, layout.len() as u32);
    v.extend_from_slice(types);
    v.extend_from_slice(layout);
    v.extend_from_slice(strings);
    v
}

fn int_type(v: &mut Vec<u8>, name: u32) {
    const INT_BYTES: u32 = 4;
    const INT_BITS: u32 = INT_BYTES * BITS_PER_BYTE;
    ty(v, name, Kind::Int, 0, false, INT_BYTES);
    push32(v, INT_BITS);
}

#[test]
fn parses_the_exact_minimal_feature_probe_shape() {
    let mut types = Vec::new();
    ty(&mut types, 1, Kind::Int, 0, false, 4);
    push32(&mut types, 1 << INT_ENCODING_SHIFT | 32);
    let raw = blob(&types, b"\0int\0");
    assert_eq!(raw.len(), 45);
    assert_eq!(parse(&raw).unwrap().type_count(), 1);
}

#[test]
fn parses_all_kinds_and_layout_records() {
    let strings = b"\0i\0s\0m\0e\0v\0sec\0f\0p\0tag\0";
    let mut t = Vec::new();
    int_type(&mut t, 1);                                      // 1
    ty(&mut t, 0, Kind::Ptr, 0, false, 1);                    // 2
    ty(&mut t, 0, Kind::Array, 0, false, 0);                  // 3
    push32(&mut t, 1); push32(&mut t, 1); push32(&mut t, 3);
    ty(&mut t, 3, Kind::Struct, 1, false, 4);                 // 4
    push32(&mut t, 5); push32(&mut t, 1); push32(&mut t, 0);
    ty(&mut t, 0, Kind::Union, 1, true, 4);                   // 5
    push32(&mut t, 5); push32(&mut t, 1); push32(&mut t, BITS_PER_BYTE << MEMBER_BITFIELD_SHIFT);
    ty(&mut t, 7, Kind::Enum, 1, false, 4);                   // 6
    push32(&mut t, 7); push32(&mut t, 1);
    ty(&mut t, 3, Kind::Fwd, 0, true, 0);                     // 7
    ty(&mut t, 1, Kind::Typedef, 0, false, 1);                // 8
    ty(&mut t, 0, Kind::Volatile, 0, false, 8);               // 9
    ty(&mut t, 0, Kind::Const, 0, false, 8);                  // 10
    ty(&mut t, 0, Kind::Restrict, 0, false, 8);               // 11
    ty(&mut t, 0, Kind::FuncProto, 1, false, 1);              // 12
    push32(&mut t, 15); push32(&mut t, 1);
    ty(&mut t, 15, Kind::Func, LINKAGE_GLOBAL, false, 12);    // 13
    ty(&mut t, 9, Kind::Var, 0, false, 1);                    // 14
    push32(&mut t, LINKAGE_STATIC);
    ty(&mut t, 11, Kind::Datasec, 1, false, 4);               // 15
    push32(&mut t, 14); push32(&mut t, 0); push32(&mut t, 4);
    ty(&mut t, 1, Kind::Float, 0, false, 4);                  // 16
    ty(&mut t, 17, Kind::DeclTag, 0, false, 4);               // 17
    push32(&mut t, 0);
    ty(&mut t, 17, Kind::TypeTag, 0, false, 1);               // 18
    ty(&mut t, 7, Kind::Enum64, 1, true, 8);                  // 19
    push32(&mut t, 7); push32(&mut t, 1); push32(&mut t, 2);
    let index = parse(&blob(&t, strings)).unwrap();
    assert_eq!(index.type_count(), 19);
    assert_eq!(index.string_range(),
        LEGACY_HEADER_LEN + t.len()..LEGACY_HEADER_LEN + t.len() + strings.len());
    assert_eq!(index.type_by_id(19).unwrap().kind, Kind::Enum64);
}

#[test]
fn rejects_header_and_section_corruption() {
    let mut types = Vec::new();
    int_type(&mut types, 1);
    let valid = blob(&types, b"\0i\0");
    let mut bad_magic = valid.clone();
    bad_magic[HEADER_MAGIC_OFF] ^= 1;
    assert_eq!(parse(&bad_magic), Err(Errno::Einval));
    let mut bad_flags = valid.clone();
    bad_flags[HEADER_FLAGS_OFF] = 1;
    assert_eq!(parse(&bad_flags), Err(Errno::Eopnotsupp));
    let mut bad_version = valid.clone();
    bad_version[HEADER_VERSION_OFF] = VERSION + 1;
    assert_eq!(parse(&bad_version), Err(Errno::Eopnotsupp));
    let mut gap = valid.clone();
    gap[HEADER_STR_OFF_OFF..HEADER_STR_OFF_OFF + WORD_LEN]
        .copy_from_slice(&(WORD_LEN as u32).to_ne_bytes());
    assert_eq!(parse(&gap), Err(Errno::Einval));
    assert_eq!(parse(&blob(&types, b"x\0")), Err(Errno::Einval));
    assert_eq!(parse(&blob(&[], b"\0")), Err(Errno::Einval));
}

#[test]
fn parses_extended_header_and_layout_metadata() {
    let mut types = Vec::new();
    int_type(&mut types, 1);
    let layout = [0, 0, 0, 0, INT_DATA_LEN as u8, 0, 0, 0];
    let strings = b"\0int\0";
    let raw = blob_with_layout(&types, strings, &layout);
    let index = parse(&raw).unwrap();
    assert_eq!(index.layouts(), &[
        Layout { info_size: 0, elem_size: 0, flags: 0 },
        Layout { info_size: INT_DATA_LEN as u8, elem_size: 0, flags: 0 },
    ]);
    assert_eq!(index.layout_range(),
        Some(HEADER_LEN + types.len()..HEADER_LEN + types.len() + layout.len()));

    let mut malformed = raw;
    malformed[HEADER_LAYOUT_LEN_OFF..HEADER_LAYOUT_LEN_OFF + WORD_LEN]
        .copy_from_slice(&(LAYOUT_DATA_LEN as u32 - 1).to_ne_bytes());
    assert_eq!(parse(&malformed), Err(Errno::Einval));
}

#[test]
fn rejects_bad_names_references_and_truncation() {
    let mut missing_name = Vec::new();
    int_type(&mut missing_name, 3);
    assert_eq!(parse(&blob(&missing_name, b"\0i\0")), Err(Errno::Einval));

    let mut bad_ref = Vec::new();
    ty(&mut bad_ref, 0, Kind::Ptr, 0, false, 2);
    assert_eq!(parse(&blob(&bad_ref, b"\0")), Err(Errno::Einval));

    let mut truncated = Vec::new();
    ty(&mut truncated, 0, Kind::Array, 0, false, 0);
    push32(&mut truncated, 1);
    assert_eq!(parse(&blob(&truncated, b"\0")), Err(Errno::Einval));
}

#[test]
fn rejects_invalid_integer_and_bitfield_layouts() {
    let mut bad_int = Vec::new();
    ty(&mut bad_int, 1, Kind::Int, 0, false, 1);
    push32(&mut bad_int, BITS_PER_BYTE + 1);
    assert_eq!(parse(&blob(&bad_int, b"\0i\0")), Err(Errno::Einval));

    let mut bad_member = Vec::new();
    int_type(&mut bad_member, 1);
    ty(&mut bad_member, 3, Kind::Struct, 1, true, 1);
    push32(&mut bad_member, 5);
    push32(&mut bad_member, 1);
    push32(&mut bad_member, BITS_PER_BYTE | (BITS_PER_BYTE << MEMBER_BITFIELD_SHIFT));
    assert_eq!(parse(&blob(&bad_member, b"\0i\0s\0m\0")), Err(Errno::Einval));
}

#[test]
fn rejects_non_integer_array_index_and_layout_cycle() {
    let mut wrong_index = Vec::new();
    ty(&mut wrong_index, 0, Kind::Ptr, 0, false, 0);
    ty(&mut wrong_index, 0, Kind::Array, 0, false, 0);
    push32(&mut wrong_index, 1); push32(&mut wrong_index, 1); push32(&mut wrong_index, 1);
    assert_eq!(parse(&blob(&wrong_index, b"\0")), Err(Errno::Einval));

    let mut overflow = Vec::new();
    int_type(&mut overflow, 1);
    ty(&mut overflow, 0, Kind::Array, 0, false, 0);
    push32(&mut overflow, 1); push32(&mut overflow, 1); push32(&mut overflow, u32::MAX);
    assert_eq!(parse(&blob(&overflow, b"\0i\0")), Err(Errno::Einval));

    let mut cycle = Vec::new();
    ty(&mut cycle, 1, Kind::Typedef, 0, false, 2);
    ty(&mut cycle, 1, Kind::Typedef, 0, false, 1);
    assert_eq!(parse(&blob(&cycle, b"\0t\0")), Err(Errno::Eexist));

    let mut recursive_ptr = Vec::new();
    ty(&mut recursive_ptr, 1, Kind::Struct, 1, false, 8);
    push32(&mut recursive_ptr, 0); push32(&mut recursive_ptr, 2); push32(&mut recursive_ptr, 0);
    ty(&mut recursive_ptr, 0, Kind::Ptr, 0, false, 1);
    assert!(parse(&blob(&recursive_ptr, b"\0s\0")).is_ok());
}

#[test]
fn reports_resolve_depth_separately_from_cycles() {
    let mut types = Vec::new();
    for id in 1..=MAX_RESOLVE_DEPTH {
        ty(&mut types, 1, Kind::Typedef, 0, false, id as u32 + 1);
    }
    int_type(&mut types, 3);
    assert_eq!(parse(&blob(&types, b"\0t\0i\0")), Err(Errno::E2big));
}

#[test]
fn rejects_var_datasec_func_and_tag_contract_violations() {
    let mut datasec = Vec::new();
    int_type(&mut datasec, 1);
    ty(&mut datasec, 3, Kind::Var, 0, false, 1);
    push32(&mut datasec, LINKAGE_STATIC);
    ty(&mut datasec, 5, Kind::Datasec, 1, false, 4);
    push32(&mut datasec, 2); push32(&mut datasec, 2); push32(&mut datasec, 4);
    assert_eq!(parse(&blob(&datasec, b"\0i\0v\0s\0")), Err(Errno::Einval));

    let mut func = Vec::new();
    int_type(&mut func, 1);
    ty(&mut func, 3, Kind::Func, LINKAGE_STATIC, false, 1);
    assert_eq!(parse(&blob(&func, b"\0i\0f\0")), Err(Errno::Einval));

    let mut tag = Vec::new();
    int_type(&mut tag, 1);
    ty(&mut tag, 3, Kind::DeclTag, 0, false, 1);
    push32(&mut tag, DECL_TAG_TYPE_COMPONENT as u32);
    assert_eq!(parse(&blob(&tag, b"\0i\0t\0")), Err(Errno::Einval));
}

#[test]
fn accepts_extern_function_and_variable_linkage() {
    let mut types = Vec::new();
    int_type(&mut types, 1);
    ty(&mut types, 0, Kind::FuncProto, 0, false, 1);
    ty(&mut types, 3, Kind::Func, LINKAGE_EXTERN, false, 2);
    ty(&mut types, 5, Kind::Var, 0, false, 1);
    push32(&mut types, LINKAGE_EXTERN);
    assert!(parse(&blob(&types, b"\0i\0f\0v\0")).is_ok());
}
