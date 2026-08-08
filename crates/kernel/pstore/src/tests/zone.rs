// The persistent-RAM zone: what survives a reboot, what is refused, and how
// the circular buffer wraps. A `Vec` stands in for the reserved physical
// region — the zone code never learns the difference, which is the point.

use super::*;
use alloc::vec;

const TAG: u32 = 0;
const ZONE: usize = 64;

fn fresh() -> Vec<u8> {
    let mut z = vec![0u8; ZONE];
    assert_eq!(attach(&mut z, TAG), Attach::Fresh);
    z
}

#[test]
fn capacity_is_the_zone_minus_its_header() {
    assert_eq!(capacity(ZONE), ZONE - ZONE_HDR_LEN);
    assert_eq!(capacity(ZONE_HDR_LEN), 0);
    assert_eq!(capacity(4), 0);
}

#[test]
fn uninitialised_memory_is_claimed_not_parsed() {
    let mut z = vec![0u8; ZONE];
    assert_eq!(attach(&mut z, TAG), Attach::Fresh);
    // Claimed: a second attach now recognises the signature.
    assert_eq!(attach(&mut z, TAG), Attach::Empty);
    assert!(read_all(&z).is_empty());
}

#[test]
fn a_foreign_signature_is_claimed() {
    let mut z = fresh();
    write(&mut z, TAG, b"payload");
    // Another zone's tag must not read this zone's contents as its own.
    assert_eq!(attach(&mut z, TAG ^ 0x99), Attach::Fresh);
    assert!(read_all(&z).is_empty());
}

#[test]
fn contents_survive_a_detach_and_reattach() {
    let mut z = fresh();
    assert_eq!(write(&mut z, TAG, b"hello reboot"), 12);
    // The reboot: the bytes stay, every in-kernel structure is gone.
    let carried = z.clone();
    let mut z2 = carried;
    assert_eq!(attach(&mut z2, TAG), Attach::Valid { bytes: 12 });
    assert_eq!(read_all(&z2), b"hello reboot".to_vec());
}

#[test]
fn a_corrupted_body_is_refused_and_discarded() {
    let mut z = fresh();
    write(&mut z, TAG, b"hello reboot");
    let mut z2 = z.clone();
    z2[ZONE_HDR_LEN + 3] ^= 0xFF;
    assert_eq!(attach(&mut z2, TAG), Attach::Invalid);
    assert!(read_all(&z2).is_empty());
}

#[test]
fn impossible_bookkeeping_is_refused() {
    let mut z = fresh();
    write(&mut z, TAG, b"abcd");
    // size beyond the data area.
    let mut z2 = z.clone();
    z2[8..12].copy_from_slice(&(capacity(ZONE) as u32 + 1).to_le_bytes());
    assert_eq!(attach(&mut z2, TAG), Attach::Invalid);
    // cursor beyond the valid bytes.
    let mut z3 = z.clone();
    z3[4..8].copy_from_slice(&99u32.to_le_bytes());
    assert_eq!(attach(&mut z3, TAG), Attach::Invalid);
}

#[test]
fn zap_empties_a_survivor() {
    let mut z = fresh();
    write(&mut z, TAG, b"gone after erase");
    zap(&mut z, TAG);
    assert_eq!(attach(&mut z, TAG), Attach::Empty);
    assert!(read_all(&z).is_empty());
}

#[test]
fn appends_accumulate_in_order() {
    let mut z = fresh();
    write(&mut z, TAG, b"one ");
    write(&mut z, TAG, b"two ");
    write(&mut z, TAG, b"three");
    assert_eq!(read_all(&z), b"one two three".to_vec());
    assert_eq!(attach(&mut z, TAG), Attach::Valid { bytes: 13 });
}

#[test]
fn a_full_zone_overwrites_its_oldest_bytes() {
    let cap = capacity(ZONE);
    let mut z = fresh();
    let a: Vec<u8> = (0..cap as u8).collect();
    write(&mut z, TAG, &a);
    assert_eq!(read_all(&z), a);
    // Eight more bytes push the eight oldest out; the survivors keep order.
    write(&mut z, TAG, b"NEWNEWNE");
    let got = read_all(&z);
    assert_eq!(got.len(), cap);
    assert_eq!(&got[..cap - 8], &a[8..]);
    assert_eq!(&got[cap - 8..], b"NEWNEWNE");
    // …and the wrapped state still validates across a reboot.
    let mut z2 = z.clone();
    assert_eq!(attach(&mut z2, TAG), Attach::Valid { bytes: cap });
    assert_eq!(read_all(&z2), got);
}

#[test]
fn a_write_longer_than_the_zone_keeps_its_tail() {
    let cap = capacity(ZONE);
    let mut z = fresh();
    let big: Vec<u8> = (0..(cap as u32 * 2)).map(|i| i as u8).collect();
    assert_eq!(write(&mut z, TAG, &big), cap);
    assert_eq!(read_all(&z), big[big.len() - cap..].to_vec());
}

#[test]
fn a_zone_with_no_room_for_a_header_stores_nothing() {
    let mut z = vec![0u8; 8];
    assert_eq!(attach(&mut z, TAG), Attach::Invalid);
    assert_eq!(write(&mut z, TAG, b"x"), 0);
    assert!(read_all(&z).is_empty());
}

#[test]
fn an_empty_write_changes_nothing() {
    let mut z = fresh();
    write(&mut z, TAG, b"kept");
    assert_eq!(write(&mut z, TAG, b""), 0);
    assert_eq!(read_all(&z), b"kept".to_vec());
}
