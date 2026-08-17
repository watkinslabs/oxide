//! What a compressed cluster costs its owner.
//!
//! The WHOLE cluster, and that is not an oversight. A compressed cluster's
//! unused slots stay RESERVED — the file goes on holding them so that a
//! rewrite which compresses worse always has somewhere to land — and a slot the
//! file holds is a slot its owner is charged for, mark or block. So compressing
//! a file changes what it occupies on the medium and not what it is charged,
//! and the two figures are meant to disagree.
//!
//! The saving is handed back deliberately, once, by the release command, which
//! gives the owner's quota back with the volume's own count. Making writeback
//! hand it back instead would give the space away silently and leave a file
//! that cannot be written, which is the state a release exists to ask for.
//!
//! Charging LESS than the whole cluster is the silent failure here, not more:
//! the block count read off the address tree already counts every mark, so a
//! quota that counted only the real blocks disagrees with the inode beside it,
//! and the release then hands back room the owner was never charged for.

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
fn a_compressed_cluster_charges_its_owner_exactly_what_a_plain_one_does() {
    // The differential is the whole assertion: the same bytes, the same
    // identity, one file compressed and one not, and the SAME charge. A quota
    // that counted only the image's blocks would make the compressed one
    // cheaper — and cheaper than the block count the inode beside it records,
    // which is the disagreement this case exists to catch.
    for algo in CODECS {
        let (mut v, ino) = with_compressed_quota(algo, LOG, 0);
        let data = compressible();

        let plain = plain_file(&mut v);
        let before = space(&mut v);
        v.write_file(plain, 0, &data).unwrap();
        v.sync_data().unwrap();
        let plain_cost = space(&mut v) - before;

        let before = space(&mut v);
        v.write_compressed(ino, 0, &data).unwrap();
        v.sync_data().unwrap();
        let cost = space(&mut v) - before;

        assert_eq!(plain_cost, CLUSTER as u64 * BLKSIZE as u64, "codec {algo}: fixture");
        assert_eq!(cost, plain_cost,
                   "codec {algo}: compressed cost {cost}, plain cost {plain_cost}");
        // And the image really is smaller, or the equality above would be
        // equality for the wrong reason.
        assert!(v.compr_blocks(ino).unwrap() > 0, "codec {algo}: nothing was saved");
    }
}

#[test]
fn releasing_the_saving_is_what_gives_the_owners_quota_back() {
    // The one place the saving reaches the owner. Give it back at writeback
    // instead and this comes back as no change at all, because there would be
    // nothing left to release.
    for algo in CODECS {
        let (mut v, ino) = with_compressed_quota(algo, LOG, 0);
        v.write_compressed(ino, 0, &compressible()).unwrap();
        v.sync_data().unwrap();
        let before = space(&mut v);
        let handed = v.release_compress_blocks(ino).unwrap();
        assert!(handed > 0, "codec {algo}: nothing was handed back");
        assert_eq!(before - space(&mut v), handed * BLKSIZE as u64, "codec {algo}");
    }
}

#[test]
fn a_limit_a_whole_cluster_exceeds_refuses_the_compressed_write_too() {
    // Two blocks' allowance and a four-block cluster. Compression does not buy
    // the owner room: every slot of the cluster is held and charged, so the
    // write is refused exactly as a plain one is — and the charge left behind
    // is only for the blocks that landed.
    for algo in CODECS {
        let units = (2 * BLKSIZE / QT_BLOCK_SIZE) as u64;
        let (mut v, ino) = with_compressed_quota(algo, LOG, units);
        assert!(v.write_compressed(ino, 0, &compressible()).unwrap() < CLUSTER * BLKSIZE,
                "codec {algo}: a cluster larger than the allowance was accepted whole");
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
