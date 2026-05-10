// DEFLATE (RFC 1951) decompressor + gzip (RFC 1952) wrapper. Used
// by the rpm crate to unwrap RPM payloads that arrive as cpio.gz.
//
// All three DEFLATE block types are supported:
//   00 stored      — uncompressed literal block
//   01 fixed Huff  — built-in Huffman tables
//   10 dynamic     — Huffman tables emitted in the block
//
// LZ77 length/distance backref tables per RFC 1951 §3.2.5.
// CRC32-IEEE per RFC 1952 §2.3.1, validated against the trailer.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;
use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    BadGzipMagic,
    UnsupportedGzipMethod,
    Truncated,
    BadBlockType,
    BadStoredLen,
    BadHuffman,
    BadBackref,
    BadCrc,
    BadIsize,
}

// ---------------- bit reader ----------------

struct BitReader<'a> {
    src: &'a [u8],
    pos: usize,   // byte position
    bb:  u64,     // bit buffer
    bn:  u32,     // bits in buffer
}

impl<'a> BitReader<'a> {
    fn new(src: &'a [u8]) -> Self { Self { src, pos: 0, bb: 0, bn: 0 } }

    fn fill(&mut self, need: u32) -> Result<(), Error> {
        while self.bn < need {
            if self.pos >= self.src.len() { return Err(Error::Truncated); }
            self.bb |= (self.src[self.pos] as u64) << self.bn;
            self.bn += 8;
            self.pos += 1;
        }
        Ok(())
    }

    fn bits(&mut self, n: u32) -> Result<u32, Error> {
        self.fill(n)?;
        let r = (self.bb & ((1u64 << n) - 1)) as u32;
        self.bb >>= n;
        self.bn -= n;
        Ok(r)
    }

    fn byte_align(&mut self) { let drop = self.bn & 7; self.bb >>= drop; self.bn -= drop; }

    fn read_u16_le(&mut self) -> Result<u16, Error> {
        let lo = self.bits(8)? as u16;
        let hi = self.bits(8)? as u16;
        Ok(lo | (hi << 8))
    }

    fn read_byte(&mut self) -> Result<u8, Error> {
        Ok(self.bits(8)? as u8)
    }

}

// ---------------- Huffman ----------------

struct Huff {
    // For up to 15-bit codes; flat decode via canonical-prefix table.
    counts: [u32; 16],
    syms:   Vec<u32>,
}

impl Huff {
    fn from_lengths(lens: &[u32]) -> Result<Huff, Error> {
        let mut counts = [0u32; 16];
        for &l in lens { if l > 15 { return Err(Error::BadHuffman); } counts[l as usize] += 1; }
        counts[0] = 0;
        let mut offsets = [0u32; 16];
        let mut acc = 0u32;
        for i in 1..16 {
            offsets[i] = acc;
            acc += counts[i];
        }
        let mut syms = alloc::vec![0u32; acc as usize];
        let mut next = offsets;
        for (sym, &l) in lens.iter().enumerate() {
            if l != 0 {
                let i = next[l as usize] as usize;
                syms[i] = sym as u32;
                next[l as usize] += 1;
            }
        }
        Ok(Huff { counts, syms })
    }

    fn decode(&self, br: &mut BitReader<'_>) -> Result<u32, Error> {
        let mut code: u32 = 0;
        let mut first: u32 = 0;
        let mut index: u32 = 0;
        for l in 1..16 {
            br.fill(1)?;
            let b = (br.bb & 1) as u32;
            br.bb >>= 1; br.bn -= 1;
            code = (code << 1) | b;
            let cnt = self.counts[l as usize];
            if code < first + cnt {
                let idx = index + (code - first);
                return Ok(self.syms[idx as usize]);
            }
            index += cnt;
            first = (first + cnt) << 1;
        }
        Err(Error::BadHuffman)
    }
}

// ---------------- length/distance tables (RFC 1951 §3.2.5) ----------------

const LEN_BASE: [u32; 29] = [
     3, 4, 5, 6, 7, 8, 9,10, 11,13,15,17, 19,23,27,31,
    35,43,51,59, 67,83,99,115, 131,163,195,227, 258];
const LEN_EXTRA: [u32; 29] = [
    0,0,0,0,0,0,0,0, 1,1,1,1, 2,2,2,2, 3,3,3,3, 4,4,4,4, 5,5,5,5, 0];
const DIST_BASE: [u32; 30] = [
       1,    2,    3,    4,    5,    7,    9,   13,
      17,   25,   33,   49,   65,   97,  129,  193,
     257,  385,  513,  769, 1025, 1537, 2049, 3073,
    4097, 6145, 8193,12289,16385,24577];
const DIST_EXTRA: [u32; 30] = [
    0,0,0,0, 1,1,2,2, 3,3,4,4, 5,5,6,6, 7,7,8,8, 9,9,10,10, 11,11,12,12, 13,13];

const CL_ORDER: [usize; 19] = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];

// ---------------- DEFLATE ----------------

fn fixed_lit() -> Huff {
    let mut lens = [0u32; 288];
    for i in 0..=143   { lens[i] = 8; }
    for i in 144..=255 { lens[i] = 9; }
    for i in 256..=279 { lens[i] = 7; }
    for i in 280..=287 { lens[i] = 8; }
    Huff::from_lengths(&lens).unwrap()
}
fn fixed_dist() -> Huff {
    let lens = [5u32; 30];
    Huff::from_lengths(&lens).unwrap()
}

fn read_dynamic_tables(br: &mut BitReader<'_>) -> Result<(Huff, Huff), Error> {
    let hlit  = br.bits(5)? as usize + 257;
    let hdist = br.bits(5)? as usize + 1;
    let hclen = br.bits(4)? as usize + 4;
    let mut cl_lens = [0u32; 19];
    for i in 0..hclen { cl_lens[CL_ORDER[i]] = br.bits(3)?; }
    let cl_huff = Huff::from_lengths(&cl_lens)?;
    let total = hlit + hdist;
    let mut lens = alloc::vec![0u32; total];
    let mut i = 0;
    while i < total {
        let sym = cl_huff.decode(br)?;
        match sym {
            0..=15 => { lens[i] = sym; i += 1; }
            16 => {
                if i == 0 { return Err(Error::BadHuffman); }
                let prev = lens[i-1];
                let r = br.bits(2)? as usize + 3;
                for _ in 0..r { if i >= total { return Err(Error::BadHuffman); } lens[i] = prev; i += 1; }
            }
            17 => { let r = br.bits(3)? as usize + 3;  for _ in 0..r { if i >= total { return Err(Error::BadHuffman); } lens[i] = 0; i += 1; } }
            18 => { let r = br.bits(7)? as usize + 11; for _ in 0..r { if i >= total { return Err(Error::BadHuffman); } lens[i] = 0; i += 1; } }
            _ => return Err(Error::BadHuffman),
        }
    }
    let lit  = Huff::from_lengths(&lens[..hlit])?;
    let dist = Huff::from_lengths(&lens[hlit..])?;
    Ok((lit, dist))
}

fn inflate_block(br: &mut BitReader<'_>, lit: &Huff, dist: &Huff, out: &mut Vec<u8>) -> Result<(), Error> {
    loop {
        let sym = lit.decode(br)?;
        if sym < 256 { out.push(sym as u8); }
        else if sym == 256 { return Ok(()); }
        else if sym <= 285 {
            let i = (sym - 257) as usize;
            let len = LEN_BASE[i] + br.bits(LEN_EXTRA[i])?;
            let d_sym = dist.decode(br)? as usize;
            if d_sym >= 30 { return Err(Error::BadBackref); }
            let back = DIST_BASE[d_sym] + br.bits(DIST_EXTRA[d_sym])?;
            let back = back as usize;
            if back == 0 || back > out.len() { return Err(Error::BadBackref); }
            // LZ77: copy len bytes starting from out.len() - back, allowing overlap.
            for _ in 0..len {
                let b = out[out.len() - back];
                out.push(b);
            }
        } else { return Err(Error::BadBackref); }
    }
}

/// Decode a raw DEFLATE stream.
/// # C: O(N)
pub fn inflate(src: &[u8]) -> Result<Vec<u8>, Error> {
    let mut br = BitReader::new(src);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let bfinal = br.bits(1)?;
        let btype  = br.bits(2)?;
        match btype {
            0 => {
                br.byte_align();
                let len  = br.read_u16_le()?;
                let nlen = br.read_u16_le()?;
                if (len ^ nlen) != 0xffff { return Err(Error::BadStoredLen); }
                for _ in 0..len { out.push(br.read_byte()?); }
            }
            1 => {
                let lit = fixed_lit(); let dist = fixed_dist();
                inflate_block(&mut br, &lit, &dist, &mut out)?;
            }
            2 => {
                let (lit, dist) = read_dynamic_tables(&mut br)?;
                inflate_block(&mut br, &lit, &dist, &mut out)?;
            }
            _ => return Err(Error::BadBlockType),
        }
        if bfinal == 1 { break; }
    }
    Ok(out)
}

// ---------------- gzip wrapper ----------------

const GZ_MAGIC: [u8; 2] = [0x1f, 0x8b];
const GZ_DEFLATE: u8 = 8;
const FHCRC: u8 = 1 << 1;
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;

/// Decode a single-member gzip stream. Validates CRC32 + ISIZE.
/// # C: O(N)
pub fn gunzip(src: &[u8]) -> Result<Vec<u8>, Error> {
    if src.len() < 18 { return Err(Error::Truncated); }
    if src[0..2] != GZ_MAGIC { return Err(Error::BadGzipMagic); }
    if src[2] != GZ_DEFLATE { return Err(Error::UnsupportedGzipMethod); }
    let flg = src[3];
    let mut p = 10;
    if (flg & FEXTRA) != 0 {
        if p + 2 > src.len() { return Err(Error::Truncated); }
        let xlen = (src[p] as usize) | ((src[p+1] as usize) << 8);
        p += 2 + xlen;
    }
    if (flg & FNAME) != 0    { while p < src.len() && src[p] != 0 { p += 1; } p += 1; }
    if (flg & FCOMMENT) != 0 { while p < src.len() && src[p] != 0 { p += 1; } p += 1; }
    if (flg & FHCRC) != 0    { p += 2; }
    if p + 8 > src.len() { return Err(Error::Truncated); }
    let body = &src[p..src.len()-8];
    let trailer = &src[src.len()-8..];
    let crc_want = u32::from_le_bytes([trailer[0],trailer[1],trailer[2],trailer[3]]);
    let isize_want = u32::from_le_bytes([trailer[4],trailer[5],trailer[6],trailer[7]]);
    let out = inflate(body)?;
    if (out.len() as u32) != isize_want { return Err(Error::BadIsize); }
    if crc32(&out) != crc_want { return Err(Error::BadCrc); }
    Ok(out)
}

// CRC32 (IEEE poly 0xEDB88320, reflected).
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for i in 0..256 {
        let mut c = i as u32;
        for _ in 0..8 { c = if c & 1 != 0 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 }; }
        table[i] = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data { crc = table[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8); }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::io::Write;

    fn pipe_gzip(input: &[u8]) -> Vec<u8> {
        let mut c = Command::new("gzip").arg("-cn").stdin(Stdio::piped()).stdout(Stdio::piped())
            .spawn().expect("gzip cmd");
        c.stdin.as_mut().unwrap().write_all(input).unwrap();
        let out = c.wait_with_output().unwrap();
        assert!(out.status.success());
        out.stdout
    }

    #[test]
    fn roundtrip_short_text() {
        let msg = b"the quick brown fox jumps over the lazy dog";
        let gz = pipe_gzip(msg);
        let out = gunzip(&gz).unwrap();
        assert_eq!(out.as_slice(), msg);
    }

    #[test]
    fn roundtrip_repetitive() {
        let mut msg = Vec::new();
        for _ in 0..256 { msg.extend_from_slice(b"hellohellohellohello"); }
        let gz = pipe_gzip(&msg);
        let out = gunzip(&gz).unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn roundtrip_binary_zero_run() {
        let msg = std::vec![0u8; 4096];
        let gz = pipe_gzip(&msg);
        let out = gunzip(&gz).unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bad = std::vec![0u8; 32];
        bad[0] = 0xff;
        assert_eq!(gunzip(&bad).unwrap_err(), Error::BadGzipMagic);
    }
}
