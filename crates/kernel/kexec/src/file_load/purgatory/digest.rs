// `kexec_calculate_store_digests`: the SHA-256 the purgatory re-computes at
// the destination, and the region table it re-computes it over.
//
// Ungated on purpose. This is the half of the verification the kernel performs
// with the bytes in hand; the other half runs in assembly on a machine that has
// already stopped. They agree or the machine halts forever, so the agreement
// has to be checkable without a boot: the same region list, the same order, the
// same zero tail.
//
// WHAT IS HASHED, and why each part of it matters:
//   - every segment's `bufsz` real bytes, in segment order;
//   - then `memsz - bufsz` ZERO bytes, because the staging path clears each
//     destination page before copying, so that is what the purgatory will read;
//   - the region row records `memsz`, not `bufsz`, for the same reason.
// The purgatory's OWN segment is excluded: the kernel patches the digest into
// it after computing it, so a self-inclusive hash could never match.

extern crate alloc;
use alloc::vec::Vec;

use crypt::Sha256;

use super::layout::{ShaRegion, DIGEST_SIZE, SHA_REGIONS_MAX};
use crate::uapi::KexecSegment;
use crate::validate::{Error, KResult};

/// Bytes of zeros fed per iteration when covering a `memsz` tail.
const ZERO_CHUNK: usize = 4096;

/// Digest over every segment but `skip`, plus the region table naming where
/// those segments land.
///
/// `segments[i].buf` is an offset into `blob` — the file-load contract — so the
/// bytes hashed here are the bytes staging will copy, read from the same place.
/// # C: O(sum of memsz)
pub fn calculate(
    segments: &[KexecSegment], blob: &[u8], skip: usize,
) -> KResult<([u8; DIGEST_SIZE], Vec<ShaRegion>)> {
    let mut h = Sha256::new();
    let mut regions: Vec<ShaRegion> = Vec::new();
    let zeros = [0u8; ZERO_CHUNK];
    for (i, s) in segments.iter().enumerate() {
        if i == skip { continue; }
        if regions.len() == SHA_REGIONS_MAX { return Err(Error::Inval); }
        let from = s.buf as usize;
        let to = from.checked_add(s.bufsz as usize).ok_or(Error::Inval)?;
        h.update(blob.get(from..to).ok_or(Error::Inval)?);
        let mut null = s.memsz.saturating_sub(s.bufsz);
        while null != 0 {
            let n = core::cmp::min(null, ZERO_CHUNK as u64);
            h.update(&zeros[..n as usize]);
            null -= n;
        }
        regions.push(ShaRegion { start: s.mem, len: s.memsz });
    }
    Ok((h.finish(), regions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn seg(buf: u64, bufsz: u64, mem: u64, memsz: u64) -> KexecSegment {
        KexecSegment { buf, bufsz, mem, memsz }
    }

    #[test]
    fn the_purgatorys_own_segment_is_excluded_from_its_own_digest() {
        // It cannot be included: the digest is written INTO it afterwards, so
        // a hash that covered it would describe bytes that no longer exist by
        // the time the purgatory reads them.
        let blob = vec![1u8; 0x2000];
        let segs = [seg(0, 0x1000, 0x3000, 0x1000), seg(0x1000, 0x1000, 0x100000, 0x1000)];
        let (_, regions) = calculate(&segs, &blob, 0).expect("both segments are in range");
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0], ShaRegion { start: 0x100000, len: 0x1000 });
    }

    #[test]
    fn a_region_records_memsz_not_bufsz() {
        // The purgatory reads `len` bytes at the destination. Recording `bufsz`
        // would hash a prefix of what it reads and the comparison would fail on
        // every kernel segment, because `init_size` always exceeds the file.
        let blob = vec![0xEEu8; 0x1000];
        let segs = [seg(0, 0x400, 0x100000, 0x4000)];
        let (_, regions) = calculate(&segs, &blob, usize::MAX).expect("in range");
        assert_eq!(regions[0].len, 0x4000);
    }

    #[test]
    fn the_tail_past_bufsz_is_hashed_as_zeros() {
        // Positive statement of the staging contract: destination pages are
        // cleared, then filled with `bufsz` bytes. A digest that stopped at
        // `bufsz` would not match what the purgatory reads.
        let blob = vec![0x5Au8; 0x40];
        let short = [seg(0, 0x40, 0x100000, 0x1000)];
        let (a, _) = calculate(&short, &blob, usize::MAX).expect("in range");

        let mut spelled = Sha256::new();
        spelled.update(&blob);
        spelled.update(&vec![0u8; 0x1000 - 0x40]);
        assert_eq!(a, spelled.finish());
    }

    #[test]
    fn segments_are_hashed_in_list_order() {
        // The purgatory walks its table top to bottom and hashes one stream.
        // Two segments swapped produce a different digest, so the order the
        // loader pushes them in is part of the contract.
        let blob = vec![0u8; 0x2000];
        let mut b = blob.clone();
        b[0] = 1;
        b[0x1000] = 2;
        let fwd = [seg(0, 0x1000, 0x10000, 0x1000), seg(0x1000, 0x1000, 0x20000, 0x1000)];
        let rev = [seg(0x1000, 0x1000, 0x20000, 0x1000), seg(0, 0x1000, 0x10000, 0x1000)];
        let (da, _) = calculate(&fwd, &b, usize::MAX).expect("in range");
        let (db, _) = calculate(&rev, &b, usize::MAX).expect("in range");
        assert_ne!(da, db);
    }

    #[test]
    fn a_segment_naming_bytes_outside_the_blob_is_refused() {
        let blob = vec![0u8; 0x10];
        let segs = [seg(0, 0x1000, 0x10000, 0x1000)];
        assert_eq!(calculate(&segs, &blob, usize::MAX).err(), Some(Error::Inval));
    }

    #[test]
    fn more_hashed_segments_than_the_table_holds_is_refused() {
        let blob = vec![0u8; 0x100];
        let mut segs = Vec::new();
        for i in 0..SHA_REGIONS_MAX + 1 { segs.push(seg(0, 1, 0x10000 * (i as u64 + 1), 1)); }
        assert_eq!(calculate(&segs, &blob, usize::MAX).err(), Some(Error::Inval));
    }
}
