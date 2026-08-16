use super::*;
use crate::volume::edit;

fn record_with(attrs: &[alloc::vec::Vec<u8>]) -> (alloc::vec::Vec<u8>, crate::record::RecordHeader) {
    let mut bytes = crate::record::format(1024, 0, 1);
    for attr in attrs {
        let header = crate::record::parse(&bytes).unwrap();
        edit::insert(&mut bytes, &header, attr).unwrap();
    }
    let header = crate::record::parse(&bytes).unwrap();
    (bytes, header)
}

fn units(name: &str) -> alloc::vec::Vec<u16> { name.encode_utf16().collect() }

#[test]
fn a_resident_attribute_round_trips() {
    let built = edit::resident(ATTR_DATA, &[], 3, false, b"payload");
    let (bytes, header) = record_with(&[built]);
    let attrs = parse_all(&bytes, &header);
    assert_eq!(attrs.len(), 1);
    let a = &attrs[0];
    assert_eq!(a.ty, ATTR_DATA);
    assert!(!a.non_resident);
    assert_eq!(a.id, 3);
    assert_eq!(a.data_size(), 7);
    let (s, e) = a.resident_span().unwrap();
    assert_eq!(&bytes[s..e], b"payload");
}

#[test]
fn a_named_attribute_keeps_its_name() {
    let built = edit::resident(ATTR_DATA, &units("stream"), 4, false, b"x");
    let (bytes, header) = record_with(&[built]);
    let attrs = parse_all(&bytes, &header);
    assert_eq!(attrs[0].name, units("stream"));
    assert!(!attrs[0].is_unnamed());
}

#[test]
fn a_nonresident_attribute_round_trips() {
    let mut runs = crate::run::Runs::new();
    runs.push(crate::run::Run { vcn: 0, lcn: 100, len: 4 });
    let built = edit::non_resident(ATTR_DATA, &[], 5, &runs, 4096 * 4, 9000, 9000, 12);
    let (bytes, header) = record_with(&[built]);
    let attrs = parse_all(&bytes, &header);
    let a = &attrs[0];
    assert!(a.non_resident);
    assert_eq!(a.data_size(), 9000);
    assert_eq!(a.valid_size(), 9000);
    let (s, e) = a.run_span().unwrap();
    assert_eq!(crate::run::unpack(&bytes[s..e], 0, 3, 1 << 20).unwrap(), runs);
}

#[test]
fn the_unnamed_data_attribute_is_the_files_own_and_a_named_one_is_a_stream() {
    // Taking the first `$DATA` returns whichever is laid out earlier rather
    // than the one asked for.
    let own = edit::resident(ATTR_DATA, &[], 1, false, b"own");
    let ads = edit::resident(ATTR_DATA, &units("alt"), 2, false, b"alternate");
    let (bytes, header) = record_with(&[own, ads]);
    let attrs = parse_all(&bytes, &header);
    let a = find(&attrs, ATTR_DATA, &[]).unwrap();
    let (s, e) = a.resident_span().unwrap();
    assert_eq!(&bytes[s..e], b"own");
    let b = find(&attrs, ATTR_DATA, &units("alt")).unwrap();
    let (s, e) = b.resident_span().unwrap();
    assert_eq!(&bytes[s..e], b"alternate");
    assert_eq!(names_of(&attrs, ATTR_DATA), alloc::vec![alloc::vec![], units("alt")]);
}

#[test]
fn attributes_are_ordered_by_type_then_name() {
    // A record whose list is out of order is one every implementation walks
    // past the attribute it was looking for.
    let data = edit::resident(ATTR_DATA, &[], 3, false, b"d");
    let std = edit::resident(ATTR_STD, &[], 1, false, &[0u8; 48]);
    let name = edit::resident(ATTR_NAME, &[], 2, true, &[0u8; 68]);
    let (bytes, header) = record_with(&[data, std, name]);
    let types: alloc::vec::Vec<u32> = parse_all(&bytes, &header).iter().map(|a| a.ty).collect();
    assert_eq!(types, alloc::vec![ATTR_STD, ATTR_NAME, ATTR_DATA]);
}

#[test]
fn segments_of_one_attribute_come_back_in_cluster_order() {
    let mut first = crate::run::Runs::new();
    first.push(crate::run::Run { vcn: 0, lcn: 100, len: 2 });
    let mut second = crate::run::Runs::new();
    second.push(crate::run::Run { vcn: 2, lcn: 200, len: 2 });
    let a = edit::non_resident(ATTR_DATA, &[], 1, &first, 8192, 16384, 16384, 12);
    let mut b = edit::non_resident(ATTR_DATA, &[], 2, &second, 8192, 16384, 16384, 12);
    // The second segment starts at cluster 2 of the file.
    b[NRES_OFF_SVCN..NRES_OFF_SVCN + 8].copy_from_slice(&2u64.to_le_bytes());
    b[NRES_OFF_EVCN..NRES_OFF_EVCN + 8].copy_from_slice(&3u64.to_le_bytes());
    let (bytes, header) = record_with(&[b, a]);
    let attrs = parse_all(&bytes, &header);
    let segs = segments(&attrs, ATTR_DATA, &[]);
    assert_eq!(segs.len(), 2);
    assert!(segs[0].is_first_segment());
    assert!(!segs[1].is_first_segment());
    // Only the FIRST segment is the one a lookup returns, because only it
    // carries the whole attribute's sizes.
    assert!(find(&attrs, ATTR_DATA, &[]).unwrap().is_first_segment());
}

#[test]
fn an_attribute_whose_data_reaches_past_its_own_size_is_refused() {
    let mut built = edit::resident(ATTR_DATA, &[], 1, false, b"payload");
    built[RES_OFF_DATA_SIZE..RES_OFF_DATA_SIZE + 4].copy_from_slice(&9999u32.to_le_bytes());
    assert!(parse(&built, 0).is_none());
}

#[test]
fn an_attribute_whose_name_reaches_outside_is_refused() {
    let mut built = edit::resident(ATTR_DATA, &units("s"), 1, false, b"x");
    built[ATTR_OFF_NAME_LEN] = 200;
    assert!(parse(&built, 0).is_none());
}

#[test]
fn the_compression_unit_is_only_read_on_a_compressed_attribute() {
    let mut runs = crate::run::Runs::new();
    runs.push(crate::run::Run { vcn: 0, lcn: 100, len: 16 });
    let mut built = edit::non_resident(ATTR_DATA, &[], 1, &runs, 0, 65536, 65536, 12);
    built[NRES_OFF_C_UNIT] = 4;
    let plain = parse(&built, 0).unwrap();
    assert_eq!(plain.compression_unit(), None, "a unit without the flag is not compression");
    built[ATTR_OFF_FLAGS..ATTR_OFF_FLAGS + 2]
        .copy_from_slice(&ATTR_FLAG_COMPRESSED.to_le_bytes());
    let packed = parse(&built, 0).unwrap();
    assert_eq!(packed.compression_unit(), Some(16));
    assert!(packed.compressed());
}

#[test]
fn the_flags_say_what_kind_of_attribute_it_is() {
    let mut built = edit::resident(ATTR_DATA, &[], 1, false, b"x");
    for (flag, check) in [(ATTR_FLAG_SPARSED, 0), (ATTR_FLAG_ENCRYPTED, 1)] {
        built[ATTR_OFF_FLAGS..ATTR_OFF_FLAGS + 2].copy_from_slice(&flag.to_le_bytes());
        let a = parse(&built, 0).unwrap();
        if check == 0 { assert!(a.sparse()); } else { assert!(a.encrypted()); }
    }
}
