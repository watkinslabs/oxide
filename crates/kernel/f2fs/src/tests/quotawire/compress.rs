//! What a compressed cluster costs its owner.
//!
//! The charge is the blocks the cluster ACTUALLY occupies, never the blocks it
//! would have occupied plain. Getting that wrong is silent on every volume
//! without quota — the segment tables and the volume's own counts are already
//! computed from the real blocks — and on a volume with one it charges a user
//! for space nobody is using, up to the whole saving.

use super::*;
use super::fixture::*;

use crate::compress::algo::{COMPRESS_LZ4, COMPRESS_LZO, COMPRESS_LZORLE, COMPRESS_ZSTD};

/// Every codec this build writes. # C: O(1)
const CODECS: [u8; 4] = [COMPRESS_LZO, COMPRESS_LZ4, COMPRESS_LZORLE, COMPRESS_ZSTD];
/// Four blocks to a cluster, which is the narrowest the format admits.
const LOG: u8 = 2;
const CLUSTER: usize = 1 << LOG;

/// A cluster's worth of bytes that every codec squeezes into one block.
/// # C: O(cluster bytes)
fn compressible() -> Vec<u8> { vec![0u8; CLUSTER * BLKSIZE] }

#[test]
fn a_compressed_cluster_charges_its_owner_less_than_a_plain_one() {
    // The differential is the whole assertion: the same bytes, the same
    // identity, one file compressed and one not. A charge computed from the
    // cluster's width would make the two equal.
    for algo in CODECS {
        let (mut v, ino) = with_compressed_quota(algo, LOG, 0);
        let data = compressible();

        let plain = plain_file(&mut v);
        let before = space(&mut v);
        v.write_file(plain, 0, &data).unwrap();
        let plain_cost = space(&mut v) - before;

        let before = space(&mut v);
        v.write_compressed(ino, 0, &data).unwrap();
        let cost = space(&mut v) - before;

        assert!(cost > 0, "codec {algo}: a compressed cluster must still be charged");
        assert!(cost < plain_cost,
                "codec {algo}: compressed cost {cost}, plain cost {plain_cost}");
        assert!(cost < CLUSTER as u64 * BLKSIZE as u64,
                "codec {algo}: charged {cost} for a cluster that does not occupy that much");
    }
}

#[test]
fn a_limit_the_plain_cluster_would_exceed_still_admits_the_compressed_one() {
    // The sharp form of the same fact, and the one a user would notice: a
    // charge taken on the cluster's width refuses this write, and the file it
    // refuses fits with room to spare.
    for algo in CODECS {
        // Two blocks' worth of allowance, in the quota file's own units.
        let units = (2 * BLKSIZE / QT_BLOCK_SIZE) as u64;
        let (mut v, ino) = with_compressed_quota(algo, LOG, units);
        assert_eq!(v.write_compressed(ino, 0, &compressible()).unwrap(),
                   CLUSTER * BLKSIZE, "codec {algo}");
        assert!(space(&mut v) <= 2 * BLKSIZE as u64, "codec {algo}");
    }
}

#[test]
fn a_cluster_that_does_not_compress_is_charged_in_full() {
    // The control for the pair above, inside the product: incompressible
    // bytes are stored plain and cost every block of the cluster, so a charge
    // that always reported a saving would be caught here.
    let mut seed = 0x1234_5678u32;
    let data: Vec<u8> = (0..CLUSTER * BLKSIZE)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            (seed >> 11) as u8
        })
        .collect();
    for algo in CODECS {
        let (mut v, ino) = with_compressed_quota(algo, LOG, 0);
        let before = space(&mut v);
        v.write_compressed(ino, 0, &data).unwrap();
        assert_eq!(space(&mut v) - before, CLUSTER as u64 * BLKSIZE as u64,
                   "codec {algo}: incompressible bytes occupy the whole cluster");
    }
}

#[test]
fn rewriting_a_compressed_cluster_charges_nothing_further() {
    // The slots already hold blocks, so the rewrite MOVES them; charging
    // again would drain a quota by rewriting one cluster repeatedly.
    for algo in CODECS {
        let (mut v, ino) = with_compressed_quota(algo, LOG, 0);
        let data = compressible();
        v.write_compressed(ino, 0, &data).unwrap();
        let before = space(&mut v);
        v.write_compressed(ino, 0, &data).unwrap();
        assert_eq!(space(&mut v), before, "codec {algo}");
    }
}
