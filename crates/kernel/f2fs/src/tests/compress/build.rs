//! Builders for the bytes the decoders are supposed to accept.
//!
//! These are the test's provenance: an encoder written against the format
//! description, independent of the decoder it feeds, so a round-trip is
//! evidence about the format rather than about one implementation agreeing
//! with itself.

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::cluster::COMPRESS_HEADER_SIZE;
use crate::uapi::BLKSIZE;

// ---- LZ4 ------------------------------------------------------------------

const LZ4_MFLIMIT: usize = 12;
const LZ4_LASTLITERALS: usize = 5;
const LZ4_MINMATCH: usize = 4;

/// A length nibble plus however many extension bytes it spills into.
pub fn lz4_len(out: &mut Vec<u8>, len: usize) -> u8 {
    if len < 15 { return len as u8; }
    let mut rest = len - 15;
    while rest >= 255 { out.push(255); rest -= 255; }
    out.push(rest as u8);
    15
}

/// A block that is one literal-only sequence: the shape every LZ4 block ends
/// with, and by itself a complete valid block.
pub fn lz4_literals(data: &[u8]) -> Vec<u8> {
    let mut ext = Vec::new();
    let nib = lz4_len(&mut ext, data.len());
    let mut out = vec![nib << 4];
    out.extend_from_slice(&ext);
    out.extend_from_slice(data);
    out
}

/// One sequence: literals, then a match at `dist` of `mlen` bytes.
///
/// Callers place these by hand, so nothing here enforces the encoder's
/// parsing restrictions — that is the point of several of the tests.
pub fn lz4_seq(out: &mut Vec<u8>, lits: &[u8], dist: u16, mlen: usize) {
    let mut lext = Vec::new();
    let lnib = lz4_len(&mut lext, lits.len());
    let mut mext = Vec::new();
    let mnib = lz4_len(&mut mext, mlen - LZ4_MINMATCH);
    out.push((lnib << 4) | mnib);
    out.extend_from_slice(&lext);
    out.extend_from_slice(lits);
    out.extend_from_slice(&dist.to_le_bytes());
    out.extend_from_slice(&mext);
}

fn hash4(b: &[u8]) -> usize {
    let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    (v.wrapping_mul(2654435761) >> 20) as usize & 0xfff
}

/// A greedy LZ4 encoder, honouring the format's two parsing restrictions: the
/// last five bytes are literals, and no match starts within twelve of the end.
pub fn lz4_compress(src: &[u8]) -> Vec<u8> {
    let n = src.len();
    if n < LZ4_MFLIMIT + 1 { return lz4_literals(src); }
    let mut out = Vec::new();
    let mut table = vec![usize::MAX; 1 << 12];
    let (mut anchor, mut i) = (0usize, 0usize);
    let limit = n - LZ4_MFLIMIT;
    while i < limit {
        let h = hash4(&src[i..i + 4]);
        let cand = table[h];
        table[h] = i;
        let hit = cand != usize::MAX && i - cand < 65536 && src[cand..cand + 4] == src[i..i + 4];
        if !hit { i += 1; continue; }
        let mut ml = LZ4_MINMATCH;
        while i + ml < n - LZ4_LASTLITERALS && src[cand + ml] == src[i + ml] { ml += 1; }
        lz4_seq(&mut out, &src[anchor..i], (i - cand) as u16, ml);
        anchor = i + ml;
        i = anchor;
    }
    let mut tail = lz4_literals(&src[anchor..]);
    out.append(&mut tail);
    out
}

// ---- LZO ------------------------------------------------------------------

/// The three bytes that end every LZO stream.
pub const LZO_END: [u8; 3] = [17, 0, 0];

/// The two bytes that declare the run-length bitstream.
pub const LZO_RLE_HEADER: [u8; 2] = [17, 1];

/// A literal run of four to eighteen bytes, valid only as a stream's first
/// command.
pub fn lzo_literals(out: &mut Vec<u8>, data: &[u8]) {
    assert!((4..=18).contains(&data.len()));
    out.push((data.len() - 3) as u8);
    out.extend_from_slice(data);
}

/// A literal run spelled out past the command byte, for runs of nineteen and
/// up.
pub fn lzo_long_literals(out: &mut Vec<u8>, data: &[u8]) {
    assert!(data.len() >= 19);
    out.push(0);
    let mut rest = data.len() - 18;
    while rest > 255 { out.push(0); rest -= 255; }
    out.push(rest as u8);
    out.extend_from_slice(data);
}

/// A two-byte match at a distance of one to 0x400, valid only where the
/// previous command carried literals of its own.
pub fn lzo_m1(out: &mut Vec<u8>, dist: usize, trail: &[u8]) {
    assert!((1..=0x400).contains(&dist) && trail.len() < 4);
    let d = dist - 1;
    out.push((((d & 3) << 2) | trail.len()) as u8);
    out.push((d >> 2) as u8);
    out.extend_from_slice(trail);
}

/// A match of three to thirty-three bytes at a distance of one to 0x4000,
/// carrying `trail` literals after it.
pub fn lzo_m3(out: &mut Vec<u8>, dist: usize, mlen: usize, trail: &[u8]) {
    assert!((3..=33).contains(&mlen) && (1..=0x4000).contains(&dist) && trail.len() < 4);
    out.push(32 | (mlen - 2) as u8);
    let word = (((dist - 1) << 2) | trail.len()) as u16;
    out.extend_from_slice(&word.to_le_bytes());
    out.extend_from_slice(trail);
}

/// A match of three to eight bytes at a distance of one to 0x800.
pub fn lzo_m2(out: &mut Vec<u8>, dist: usize, mlen: usize, trail: &[u8]) {
    assert!((3..=8).contains(&mlen) && (1..=0x800).contains(&dist) && trail.len() < 4);
    let d = dist - 1;
    out.push((((mlen - 1) << 5) | ((d & 7) << 2) | trail.len()) as u8);
    out.push((d >> 3) as u8);
    out.extend_from_slice(trail);
}

/// A match of three to nine bytes at a distance of 0x4001 to 0xbfff. The one
/// distance below that, spelled the same way, is the stream's end marker.
pub fn lzo_m4(out: &mut Vec<u8>, dist: usize, mlen: usize, trail: &[u8]) {
    assert!((3..=9).contains(&mlen) && (0x4001..=0xbfff).contains(&dist) && trail.len() < 4);
    let d = dist - 0x4000;
    let high = if d >= 0x4000 { 8 } else { 0 };
    let low = d - if high != 0 { 0x4000 } else { 0 };
    out.push((16 | high | (mlen - 2)) as u8);
    let word = ((low << 2) | trail.len()) as u16;
    out.extend_from_slice(&word.to_le_bytes());
    out.extend_from_slice(trail);
}

/// A run of four to 2051 zero bytes, which only the run-length bitstream has.
pub fn lzo_zero_run(out: &mut Vec<u8>, len: usize, trail: &[u8]) {
    assert!((4..=2051).contains(&len) && trail.len() < 4);
    let v = len - 4;
    out.push((0x18 | (v & 7)) as u8);
    out.push(0xfc | trail.len() as u8);
    out.push(0xff);
    out.push((v >> 3) as u8);
    out.extend_from_slice(trail);
}

/// A whole cluster of one repeated byte, as an LZO stream: a short literal run
/// seeded with it, then matches at distance one until the cluster is full.
pub fn lzo_uniform(len: usize, byte: u8) -> Vec<u8> {
    let mut out = Vec::new();
    lzo_literals(&mut out, &[byte; 4]);
    let mut have = 4usize;
    while have < len {
        let take = (len - have).min(33);
        // A match must be at least three bytes, so the last one absorbs any
        // remainder rather than leaving one or two bytes behind.
        let take = if len - have - take < 3 && len - have != take { len - have - 3 } else { take };
        lzo_m3(&mut out, 1, take, &[]);
        have += take;
    }
    out.extend_from_slice(&LZO_END);
    out
}

// ---- Clusters -------------------------------------------------------------

/// A stored cluster image: the header, the codec's bytes, and the padding out
/// to whole blocks that the medium always has.
pub fn image(cdata: &[u8], chksum: u32) -> Vec<u8> {
    image_with_clen(cdata, cdata.len() as u32, chksum)
}

/// The same, with a length word the caller chooses, so a header can be made to
/// disagree with what follows it.
pub fn image_with_clen(cdata: &[u8], clen: u32, chksum: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(COMPRESS_HEADER_SIZE + cdata.len());
    out.extend_from_slice(&clen.to_le_bytes());
    out.extend_from_slice(&chksum.to_le_bytes());
    out.resize(COMPRESS_HEADER_SIZE, 0);
    out.extend_from_slice(cdata);
    let blocks = out.len().div_ceil(BLKSIZE).max(1);
    out.resize(blocks * BLKSIZE, 0);
    out
}

/// Bytes that compress but are not uniform, so a round-trip exercises matches,
/// literal runs and extended lengths rather than one long run.
pub fn patterned(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x: u32 = 0x1234_5678;
    while v.len() < len {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        let word = (x >> 16) as u16;
        // Every other stretch repeats, so the encoder finds real matches.
        if word % 3 == 0 {
            let n = (word as usize % 40) + 8;
            let b = (word & 0xff) as u8;
            for _ in 0..n { v.push(b); }
        } else {
            for k in 0..8u32 { v.push((word as u32).wrapping_add(k) as u8); }
        }
    }
    v.truncate(len);
    v
}
