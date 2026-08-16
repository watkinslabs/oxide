use super::*;
use alloc::vec;
use alloc::vec::Vec;

/// Encode a bitmap in the wire format so the reader can be driven directly.
fn wire(highbit: u32, chunks: &[(u32, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAP_UNIT.to_le_bytes());
    out.extend_from_slice(&highbit.to_le_bytes());
    out.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
    for (start, map) in chunks {
        out.extend_from_slice(&start.to_le_bytes());
        out.extend_from_slice(&map.to_le_bytes());
    }
    out
}

fn read(bytes: &[u8]) -> Result<Ebitmap> { Ebitmap::read(&mut Reader::new(bytes)) }

fn from_bits(bits: &[u32]) -> Ebitmap {
    let mut e = Ebitmap::new();
    for b in bits { e.set(*b, true); }
    e
}

#[test]
fn an_empty_bitmap_has_nothing_set() {
    let e = Ebitmap::new();
    assert!(e.is_empty());
    assert_eq!(e.count(), 0);
    assert_eq!(e.highbit(), 0);
    assert!(!e.get(0));
    assert!(!e.get(u32::MAX - 1));
}

#[test]
fn set_and_get_round_trip_across_chunk_boundaries() {
    let bits = [0u32, 1, 63, 64, 65, 127, 128, 383, 384, 1000];
    let e = from_bits(&bits);
    for b in 0..1100u32 {
        assert_eq!(e.get(b), bits.contains(&b), "bit {b}");
    }
    assert_eq!(e.count(), bits.len() as u32);
}

#[test]
fn iter_yields_set_bits_in_ascending_order() {
    let bits = vec![5u32, 63, 64, 200, 4095];
    let e = from_bits(&bits);
    assert_eq!(e.iter().collect::<Vec<_>>(), bits);
}

#[test]
fn clearing_the_last_bit_of_a_chunk_removes_it() {
    let mut e = from_bits(&[70, 71]);
    e.set(70, false);
    assert_eq!(e.iter().collect::<Vec<_>>(), vec![71]);
    e.set(71, false);
    assert!(e.is_empty());
    assert!(!e.get(71));
}

#[test]
fn contains_is_a_superset_test_not_an_intersection_test() {
    let big = from_bits(&[1, 2, 3, 100, 200]);
    let small = from_bits(&[1, 100]);
    let overlapping = from_bits(&[1, 999]);
    assert!(big.contains(&small));
    assert!(!small.contains(&big));
    assert!(!big.contains(&overlapping),
            "a shared member is not containment; treating it as one would grant every category");
    assert!(big.contains(&Ebitmap::new()), "everything contains the empty set");
}

#[test]
fn contains_detects_a_missing_bit_within_a_shared_chunk() {
    let a = from_bits(&[1, 2]);
    let b = from_bits(&[1, 2, 3]);
    assert!(!a.contains(&b));
    assert!(b.contains(&a));
}

#[test]
fn intersects_is_symmetric_and_ignores_disjoint_chunks() {
    let a = from_bits(&[1, 500]);
    let b = from_bits(&[500, 900]);
    let c = from_bits(&[2, 900]);
    assert!(a.intersects(&b) && b.intersects(&a));
    assert!(!a.intersects(&c) && !c.intersects(&a));
    assert!(!a.intersects(&Ebitmap::new()));
}

#[test]
fn reading_an_empty_bitmap_yields_the_empty_set() {
    let e = read(&wire(0, &[])).expect("empty bitmap");
    assert!(e.is_empty());
    assert_eq!(e.highbit(), 0);
}

#[test]
fn reading_a_single_chunk_recovers_its_bits() {
    let e = read(&wire(NODE_BITS, &[(0, 0b1011)])).expect("one chunk");
    assert_eq!(e.iter().collect::<Vec<_>>(), vec![0, 1, 3]);
    assert_eq!(e.highbit(), NODE_BITS);
}

#[test]
fn reading_recovers_chunks_spread_across_several_nodes() {
    let e = read(&wire(NODE_BITS * 2, &[(0, 1), (320, 1 << 63), (384, 3)]))
        .expect("multi-node bitmap");
    assert_eq!(e.iter().collect::<Vec<_>>(), vec![0, 383, 384, 385]);
}

#[test]
fn a_declared_high_bit_is_rounded_up_to_a_whole_node() {
    let e = read(&wire(1, &[(0, 1)])).expect("rounded high bit");
    assert_eq!(e.highbit(), NODE_BITS,
               "the extent is node-granular; a smaller value would reject valid images");
}

#[test]
fn a_wrong_map_unit_is_refused() {
    let mut bytes = wire(NODE_BITS, &[(0, 1)]);
    bytes[0..4].copy_from_slice(&32u32.to_le_bytes());
    assert_eq!(read(&bytes), Err(Error::Malformed));
}

#[test]
fn a_nonzero_count_with_a_zero_high_bit_is_refused() {
    assert_eq!(read(&wire(0, &[(0, 1)])), Err(Error::Malformed));
}

#[test]
fn a_zero_count_with_a_nonzero_high_bit_is_refused() {
    assert_eq!(read(&wire(NODE_BITS, &[])), Err(Error::Malformed));
}

#[test]
fn an_unaligned_start_bit_is_refused() {
    assert_eq!(read(&wire(NODE_BITS, &[(1, 1)])), Err(Error::Malformed));
}

#[test]
fn a_start_bit_past_the_declared_extent_is_refused() {
    assert_eq!(read(&wire(NODE_BITS, &[(384, 1)])), Err(Error::Malformed));
}

#[test]
fn a_repeated_or_descending_start_bit_is_refused() {
    assert_eq!(read(&wire(NODE_BITS, &[(0, 1), (0, 2)])), Err(Error::Malformed));
    assert_eq!(read(&wire(NODE_BITS, &[(64, 1), (0, 2)])), Err(Error::Malformed));
}

#[test]
fn an_empty_chunk_is_refused() {
    assert_eq!(read(&wire(NODE_BITS, &[(0, 0)])), Err(Error::Malformed));
}

#[test]
fn a_final_chunk_short_of_the_declared_extent_is_refused() {
    assert_eq!(read(&wire(NODE_BITS * 2, &[(0, 1)])), Err(Error::Malformed),
               "the writer and reader must agree on the extent");
}

#[test]
fn a_truncated_image_is_refused_rather_than_read_short() {
    let full = wire(NODE_BITS, &[(0, 0xdead_beef)]);
    for cut in 0..full.len() {
        assert!(read(&full[..cut]).is_err(), "prefix of length {cut} must be refused");
    }
    assert!(read(&full).is_ok());
}

#[test]
fn a_declared_count_far_beyond_the_image_does_not_over_allocate() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAP_UNIT.to_le_bytes());
    bytes.extend_from_slice(&NODE_BITS.to_le_bytes());
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(read(&bytes).is_err());
}
