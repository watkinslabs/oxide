use super::*;
use alloc::vec;
use alloc::vec::Vec;

fn key(s: u16, t: u16, c: u16, spec: u16) -> Key {
    Key { source_type: s, target_type: t, target_class: c, specified: spec }
}

fn rule(s: u16, t: u16, c: u16, spec: u16, data: u32) -> Rule {
    Rule { key: key(s, t, c, spec), datum: Datum::Word(data) }
}

/// Encode one current-format item.
fn item(s: u16, t: u16, c: u16, spec: u16, data: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for v in [s, t, c, spec] { out.extend_from_slice(&v.to_le_bytes()); }
    out.extend_from_slice(&data.to_le_bytes());
    out
}

fn table(items: &[Vec<u8>], version: u32) -> Result<Avtab> {
    let mut bytes = (items.len() as u32).to_le_bytes().to_vec();
    for i in items { bytes.extend_from_slice(i); }
    Avtab::read(&mut Reader::new(&bytes), version)
}

const V_CURRENT: u32 = crate::uapi::version::POLICYDB_VERSION_COND_XPERMS;

#[test]
fn the_kind_bit_set_is_exactly_the_specifier_minus_the_enabled_bit() {
    let k = key(1, 2, 3, AVTAB_ALLOWED | AVTAB_ENABLED);
    assert_eq!(k.kind(), AVTAB_ALLOWED);
    assert!(k.enabled());
    assert!(!key(1, 2, 3, AVTAB_ALLOWED).enabled());
}

#[test]
fn a_specifier_must_name_exactly_one_kind() {
    assert!(key(1, 2, 3, AVTAB_ALLOWED).kind_is_singular());
    assert!(key(1, 2, 3, AVTAB_TRANSITION | AVTAB_ENABLED).kind_is_singular());
    assert!(!key(1, 2, 3, AVTAB_ALLOWED | AVTAB_AUDITDENY).kind_is_singular(),
            "two kinds in one specifier would make the datum ambiguous");
    assert!(!key(1, 2, 3, 0).kind_is_singular());
    assert!(!key(1, 2, 3, 0x0008).kind_is_singular(), "an undefined bit is not a kind");
}

#[test]
fn insert_and_search_recover_a_rule_by_its_full_triple() {
    let mut t = Avtab::with_capacity(8);
    t.insert(rule(1, 2, 3, AVTAB_ALLOWED, 0xf));
    let found: Vec<u32> = t.search(&key(1, 2, 3, AVTAB_AV)).map(|r| r.datum.word()).collect();
    assert_eq!(found, vec![0xf]);
}

#[test]
fn a_lookup_differing_in_any_one_component_of_the_triple_misses() {
    let mut t = Avtab::with_capacity(8);
    t.insert(rule(1, 2, 3, AVTAB_ALLOWED, 0xf));
    for k in [key(9, 2, 3, AVTAB_AV), key(1, 9, 3, AVTAB_AV), key(1, 2, 9, AVTAB_AV)] {
        assert_eq!(t.search(&k).count(), 0,
                   "a partial-key match would return another subject's rule");
    }
}

#[test]
fn search_filters_by_kind() {
    let mut t = Avtab::with_capacity(8);
    t.insert(rule(1, 2, 3, AVTAB_ALLOWED, 0xf));
    t.insert(rule(1, 2, 3, AVTAB_AUDITDENY, 0x3));
    t.insert(rule(1, 2, 3, AVTAB_TRANSITION, 7));
    assert_eq!(t.search(&key(1, 2, 3, AVTAB_AV)).count(), 2);
    assert_eq!(t.search(&key(1, 2, 3, AVTAB_TRANSITION)).count(), 1);
    assert_eq!(t.search(&key(1, 2, 3, AVTAB_MEMBER)).count(), 0);
}

#[test]
fn search_matches_a_conditional_rule_regardless_of_its_enabled_bit() {
    let mut t = Avtab::with_capacity(8);
    t.insert(rule(1, 2, 3, AVTAB_ALLOWED | AVTAB_ENABLED, 0xf));
    assert_eq!(t.search(&key(1, 2, 3, AVTAB_AV)).count(), 1,
               "the enabled bit gates the decision, not the lookup");
}

#[test]
fn insert_unique_refuses_an_exact_duplicate_but_allows_a_different_kind() {
    let mut t = Avtab::with_capacity(8);
    assert!(t.insert_unique(rule(1, 2, 3, AVTAB_ALLOWED, 1)).is_ok());
    assert_eq!(t.insert_unique(rule(1, 2, 3, AVTAB_ALLOWED, 2)), Err(Error::Duplicate));
    assert!(t.insert_unique(rule(1, 2, 3, AVTAB_AUDITALLOW, 2)).is_ok());
    assert_eq!(t.len(), 2);
}

#[test]
fn many_rules_all_remain_findable_whatever_the_bucket_count() {
    for nel in [1u32, 4, 17, 256, 1000] {
        let mut t = Avtab::with_capacity(nel);
        for i in 0..nel as u16 {
            t.insert(rule(i, i.wrapping_mul(3), i % 7, AVTAB_ALLOWED, i as u32));
        }
        for i in 0..nel as u16 {
            let got: Vec<u32> = t.search(&key(i, i.wrapping_mul(3), i % 7, AVTAB_AV))
                .map(|r| r.datum.word()).collect();
            assert!(got.contains(&(i as u32)), "nel={nel} rule {i} lost");
        }
    }
}

#[test]
fn reading_a_current_format_table_recovers_every_item() {
    let t = table(&[item(1, 2, 3, AVTAB_ALLOWED, 0xff),
                    item(4, 5, 6, AVTAB_TRANSITION, 9)], V_CURRENT).expect("table");
    assert_eq!(t.len(), 2);
    assert_eq!(t.search(&key(4, 5, 6, AVTAB_TRANSITION)).next().unwrap().datum.word(), 9);
}

#[test]
fn an_empty_table_is_refused() {
    let bytes = 0u32.to_le_bytes();
    assert_eq!(Avtab::read(&mut Reader::new(&bytes), V_CURRENT).err(), Some(Error::Malformed));
}

#[test]
fn a_duplicate_item_in_the_image_is_refused() {
    let dup = item(1, 2, 3, AVTAB_ALLOWED, 1);
    assert_eq!(table(&[dup.clone(), dup], V_CURRENT).err(), Some(Error::Duplicate));
}

#[test]
fn an_item_naming_two_kinds_is_refused() {
    assert_eq!(table(&[item(1, 2, 3, AVTAB_ALLOWED | AVTAB_TRANSITION, 1)], V_CURRENT).err(),
               Some(Error::Malformed));
}

#[test]
fn extended_permissions_are_refused_before_the_version_that_defines_them() {
    let mut bytes = Vec::new();
    for v in [1u16, 2, 3, AVTAB_XPERMS_ALLOWED] { bytes.extend_from_slice(&v.to_le_bytes()); }
    bytes.push(AVTAB_XPERMS_IOCTLFUNCTION);
    bytes.push(0);
    for _ in 0..XPERMS_WORDS { bytes.extend_from_slice(&0u32.to_le_bytes()); }
    let old = crate::uapi::version::POLICYDB_VERSION_XPERMS_IOCTL - 1;
    assert_eq!(table(&[bytes.clone()], old).err(), Some(Error::Malformed));
    assert!(table(&[bytes], V_CURRENT).is_ok());
}

#[test]
fn an_extended_permission_bitmap_round_trips_its_bits() {
    let mut bytes = Vec::new();
    for v in [1u16, 2, 3, AVTAB_XPERMS_ALLOWED] { bytes.extend_from_slice(&v.to_le_bytes()); }
    bytes.push(AVTAB_XPERMS_IOCTLFUNCTION);
    bytes.push(0x42);
    let mut words = [0u32; XPERMS_WORDS];
    words[0] = 0b1010;
    words[7] = 1 << 31;
    for w in words { bytes.extend_from_slice(&w.to_le_bytes()); }
    let t = table(&[bytes], V_CURRENT).expect("xperms table");
    let r = t.search(&key(1, 2, 3, AVTAB_XPERMS)).next().expect("rule");
    let x = r.datum.xperms().expect("xperms datum");
    assert_eq!(x.driver, 0x42);
    assert!(x.get(1) && x.get(3) && x.get(255));
    assert!(!x.get(0) && !x.get(2) && !x.get(254));
}

#[test]
fn a_conditional_extended_permission_is_refused_before_the_version_that_allows_it() {
    let mut bytes = Vec::new();
    for v in [1u16, 2, 3, AVTAB_XPERMS_ALLOWED] { bytes.extend_from_slice(&v.to_le_bytes()); }
    bytes.push(AVTAB_XPERMS_IOCTLFUNCTION);
    bytes.push(0);
    for _ in 0..XPERMS_WORDS { bytes.extend_from_slice(&0u32.to_le_bytes()); }
    let v = crate::uapi::version::POLICYDB_VERSION_COND_XPERMS - 1;
    let mut emitted = 0usize;
    let r = read_item(&mut Reader::new(&bytes), v, true, &mut |_| { emitted += 1; Ok(()) });
    assert_eq!(r, Err(Error::Malformed));
    assert_eq!(emitted, 0);
}

#[test]
fn a_pre_hashed_record_expands_into_one_rule_per_kind_bit() {
    let mut bytes = Vec::new();
    // items, source, target, class, combined kinds, then one datum per kind.
    for v in [6u32, 1, 2, 3, (AVTAB_ALLOWED | AVTAB_AUDITDENY) as u32] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    bytes.extend_from_slice(&0xaau32.to_le_bytes());   // allowed, listed first
    bytes.extend_from_slice(&0xbbu32.to_le_bytes());   // auditdeny, listed second
    let mut got: Vec<(u16, u32)> = Vec::new();
    let old = crate::uapi::version::POLICYDB_VERSION_AVTAB - 1;
    read_item(&mut Reader::new(&bytes), old, false,
              &mut |r| { got.push((r.key.kind(), r.datum.word())); Ok(()) }).expect("expand");
    assert_eq!(got, vec![(AVTAB_ALLOWED, 0xaa), (AVTAB_AUDITDENY, 0xbb)],
               "the data words follow a fixed kind order, not the bit order of the field");
}

#[test]
fn a_pre_hashed_record_carries_its_enabled_bit_into_every_expanded_rule() {
    let mut bytes = Vec::new();
    for v in [5u32, 1, 2, 3, AVTAB_ENABLED_OLD | AVTAB_ALLOWED as u32] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    bytes.extend_from_slice(&1u32.to_le_bytes());
    let old = crate::uapi::version::POLICYDB_VERSION_AVTAB - 1;
    let mut enabled = Vec::new();
    read_item(&mut Reader::new(&bytes), old, false,
              &mut |r| { enabled.push(r.key.enabled()); Ok(()) }).expect("expand");
    assert_eq!(enabled, vec![true]);
}

#[test]
fn a_pre_hashed_record_requesting_extended_permissions_is_refused() {
    let mut bytes = Vec::new();
    for v in [5u32, 1, 2, 3, AVTAB_XPERMS_ALLOWED as u32] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    bytes.extend_from_slice(&0u32.to_le_bytes());
    let old = crate::uapi::version::POLICYDB_VERSION_AVTAB - 1;
    assert_eq!(read_item(&mut Reader::new(&bytes), old, false, &mut |_| Ok(())),
               Err(Error::Malformed));
}

#[test]
fn a_truncated_table_is_refused_rather_than_read_short() {
    let mut bytes = 2u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&item(1, 2, 3, AVTAB_ALLOWED, 1));
    bytes.extend_from_slice(&item(4, 5, 6, AVTAB_ALLOWED, 2));
    for cut in 0..bytes.len() {
        assert!(Avtab::read(&mut Reader::new(&bytes[..cut]), V_CURRENT).is_err(),
                "prefix {cut} must be refused");
    }
    assert!(Avtab::read(&mut Reader::new(&bytes), V_CURRENT).is_ok());
}

#[test]
fn a_default_table_is_usable_rather_than_a_trap() {
    // A derived default would leave no buckets and a zero mask, so the first
    // insert would index a bucket that does not exist.
    let mut t = Avtab::default();
    assert!(t.is_empty());
    assert_eq!(t.search(&key(1, 2, 3, AVTAB_AV)).count(), 0);
    t.insert(rule(1, 2, 3, AVTAB_ALLOWED, 5));
    assert_eq!(t.search(&key(1, 2, 3, AVTAB_AV)).next().unwrap().datum.word(), 5);
}
