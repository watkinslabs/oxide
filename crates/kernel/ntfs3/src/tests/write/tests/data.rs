use super::*;

#[test]
fn a_small_written_file_stays_resident_and_reads_back() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "small.txt", now()).unwrap();
    let payload = b"resident payload";
    v.write_file(made.reference.number, 0, payload, now()).unwrap();
    assert_eq!(v.read_whole(made.reference.number).unwrap(), payload);
    let (bytes, attrs) = v.read_record(made.reference.number).unwrap();
    let attr = crate::attrib::find(&attrs, ATTR_DATA, &[]).unwrap();
    assert!(!attr.non_resident, "a small file must stay in its record");
    let _ = bytes;
}

#[test]
fn a_file_grown_past_its_record_moves_out_into_clusters() {
    // The transition is the point: a write that only ever grows the resident
    // form fails at the record's edge and calls the volume full.
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "big.bin", now()).unwrap();
    let payload: alloc::vec::Vec<u8> = (0..CLUSTER * 2 + 5).map(|i| (i % 251) as u8).collect();
    let size = v.write_file(made.reference.number, 0, &payload, now()).unwrap();
    assert_eq!(size, payload.len() as u64);
    let (_, attrs) = v.read_record(made.reference.number).unwrap();
    assert!(crate::attrib::find(&attrs, ATTR_DATA, &[]).unwrap().non_resident);
    assert_eq!(v.read_whole(made.reference.number).unwrap(), payload);
}

#[test]
fn a_resident_file_that_grows_keeps_the_bytes_it_had() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "grow.txt", now()).unwrap();
    v.write_file(made.reference.number, 0, b"first", now()).unwrap();
    let tail: alloc::vec::Vec<u8> = alloc::vec![b'x'; CLUSTER];
    v.write_file(made.reference.number, 5, &tail, now()).unwrap();
    let got = v.read_whole(made.reference.number).unwrap();
    assert_eq!(&got[..5], b"first");
    assert_eq!(&got[5..], &tail[..]);
}

#[test]
fn a_write_into_the_middle_keeps_the_bytes_either_side() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "patch.bin", now()).unwrap();
    v.write_file(made.reference.number, 0, &alloc::vec![1u8; CLUSTER * 2], now()).unwrap();
    v.write_file(made.reference.number, 100, &[2u8; 8], now()).unwrap();
    let got = v.read_whole(made.reference.number).unwrap();
    assert_eq!(&got[..100], &alloc::vec![1u8; 100][..]);
    assert_eq!(&got[100..108], &[2u8; 8]);
    assert_eq!(&got[108..], &alloc::vec![1u8; CLUSTER * 2 - 108][..]);
}

#[test]
fn a_write_past_the_end_leaves_zeros_not_the_previous_owners_bytes() {
    let mut v = test_image::empty();
    let scratch = v.create_file(MFT_REC_ROOT, "scratch", now()).unwrap();
    v.write_file(scratch.reference.number, 0, &alloc::vec![0xAB; CLUSTER * 2], now()).unwrap();
    v.unlink(MFT_REC_ROOT, "scratch", now()).unwrap();

    let made = v.create_file(MFT_REC_ROOT, "sparse", now()).unwrap();
    v.write_file(made.reference.number, CLUSTER as u64, b"tail", now()).unwrap();
    let got = v.read_whole(made.reference.number).unwrap();
    assert_eq!(got.len(), CLUSTER + 4);
    assert!(got[..CLUSTER].iter().all(|b| *b == 0), "the gap kept old bytes");
    assert_eq!(&got[CLUSTER..], b"tail");
}

#[test]
fn shortening_a_file_releases_the_clusters_it_no_longer_needs() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "shrink.bin", now()).unwrap();
    v.write_file(made.reference.number, 0, &alloc::vec![3u8; CLUSTER * 4], now()).unwrap();
    let used = v.used_clusters();
    v.truncate_file(made.reference.number, CLUSTER as u64, now()).unwrap();
    assert_eq!(v.used_clusters(), used - 3);
    assert_eq!(v.read_whole(made.reference.number).unwrap(), alloc::vec![3u8; CLUSTER]);
}

#[test]
fn lengthening_a_file_allocates_and_zeroes() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "extend.bin", now()).unwrap();
    v.write_file(made.reference.number, 0, &alloc::vec![7u8; CLUSTER], now()).unwrap();
    v.truncate_file(made.reference.number, CLUSTER as u64 * 3, now()).unwrap();
    let got = v.read_whole(made.reference.number).unwrap();
    assert_eq!(got.len(), CLUSTER * 3);
    assert_eq!(&got[..CLUSTER], &alloc::vec![7u8; CLUSTER][..]);
    assert!(got[CLUSTER..].iter().all(|b| *b == 0));
}
