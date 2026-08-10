// Hosted provenance for the shipped purgatory bytes.

use super::super::layout::*;
use super::*;
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

extern "C" {
    fn oxide_purgatory_sha256(p: *const u8, n: usize, out: *mut u8);
}

fn asm_sha(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: `oxide_purgatory_sha256` reads `n` bytes at `p` and writes 32
    // at `out`, both of which are live local buffers of exactly those sizes.
    unsafe { oxide_purgatory_sha256(data.as_ptr(), data.len(), out.as_mut_ptr()) };
    out
}

#[test]
fn the_blob_is_exactly_the_length_the_layout_declares() {
    // The `.org` directives make an overrun a build failure; this makes a
    // layout constant that drifted away from the assembly a test failure.
    assert_eq!(bytes().len(), BLOB_LEN);
}

#[test]
fn the_layout_offsets_name_the_bytes_the_assembly_emitted() {
    // Every constant `layout.rs` publishes is checked against the shipped
    // blob, because nothing else ties the two together: a wrong offset is
    // not a compile error, it is a machine that halts forever.
    let b = bytes();
    assert!(b[OFF_ENTRY_REGS..OFF_ENTRY_REGS + ENTRY_REGS_SIZE].iter().all(|&x| x == 0));
    assert!(b[OFF_DIGEST..OFF_DIGEST + DIGEST_SIZE].iter().all(|&x| x == 0));
    assert!(b[OFF_SHA_REGIONS..OFF_SHA_REGIONS + SHA_REGIONS_MAX * SHA_REGION_SIZE]
        .iter().all(|&x| x == 0));
    // GDT: null descriptor, then the 64-bit code descriptor at CODE_SEL and
    // the flat data descriptor at DATA_SEL.
    assert_eq!(&b[OFF_GDT..OFF_GDT + 16], &[0u8; 16]);
    assert_eq!(&b[OFF_GDT + CODE_SEL as usize..OFF_GDT + CODE_SEL as usize + 8],
               &[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xAF, 0x00]);
    assert_eq!(&b[OFF_GDT + DATA_SEL as usize..OFF_GDT + DATA_SEL as usize + 8],
               &[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x92, 0xCF, 0x00]);
    // The `lgdt` operand's limit is GDT_SIZE - 1; its base is filled in at
    // run time, so it ships as zero.
    assert_eq!(u16::from_le_bytes(b[OFF_GDTR..OFF_GDTR + 2].try_into().unwrap()),
               GDT_SIZE as u16 - 1);
    assert_eq!(&b[OFF_GDTR + 2..OFF_GDTR + 10], &[0u8; 8]);
    assert_eq!(&b[OFF_H0..OFF_H0 + 4], &0x6a09e667u32.to_le_bytes());
    assert_eq!(&b[OFF_K..OFF_K + 4], &0x428a2f98u32.to_le_bytes());
    assert_eq!(&b[OFF_K + 252..OFF_K + 256], &0xc67178f2u32.to_le_bytes());
    // The entry point is the `cli` the state at entry demands.
    assert_eq!(b[OFF_CODE], 0xFA);
    // Both stacks ship zeroed, so the segment's content does not depend on
    // anything clearing the destination.
    assert!(b[OFF_PURG_STACK..BLOB_LEN].iter().all(|&x| x == 0));
}

#[test]
fn the_blobs_own_sha256_matches_the_published_vectors() {
    // FIPS 180-4 vectors. If this drifts, the purgatory computes a digest
    // the kernel never predicts and every kexec halts at the compare.
    let abc = asm_sha(b"abc");
    assert_eq!(&abc[..4], &[0xba, 0x78, 0x16, 0xbf]);
    assert_eq!(&abc[28..], &[0xf2, 0x00, 0x15, 0xad]);
    let empty = asm_sha(b"");
    assert_eq!(&empty[..4], &[0xe3, 0xb0, 0xc4, 0x42]);
    assert_eq!(&empty[28..], &[0x78, 0x52, 0xb8, 0x55]);
}

#[test]
fn the_blobs_sha256_agrees_with_the_kernel_side_one_at_every_block_boundary() {
    // The kernel predicts the digest with one implementation and the
    // purgatory recomputes it with another; they must agree for EVERY
    // length, and the lengths that break a hand-written padding path are
    // the ones either side of 55, 56, 63, 64 and 119.
    for n in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 4096, 4097] {
        let data: Vec<u8> = (0..n).map(|i| (i * 7 + 1) as u8).collect();
        assert_eq!(asm_sha(&data), crypt::sha256::sha256(&data), "length {n} disagrees");
    }
}

#[test]
fn the_blobs_sha256_streams_a_region_list_the_same_way_the_kernel_does() {
    // The purgatory hashes region after region into ONE digest. The kernel
    // side does the same with successive `update` calls, so a concatenation
    // must hash identically to the pieces.
    let a = vec![0xA5u8; 100];
    let b = vec![0x5Au8; 4096];
    let mut joined = a.clone();
    joined.extend_from_slice(&b);
    let mut h = crypt::Sha256::new();
    h.update(&a);
    h.update(&b);
    assert_eq!(asm_sha(&joined), h.finish());
}
