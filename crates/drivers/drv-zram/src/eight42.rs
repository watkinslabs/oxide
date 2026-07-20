//! Linux software-842 compatible compressed-page codec.

use alloc::vec::Vec;

use block::{BlockError, KResult};

const OP_BITS: u8 = 5;
const REPEAT_BITS: u8 = 6;
const SHORT_DATA_BITS: u8 = 3;
const I2_BITS: u8 = 8;
const I4_BITS: u8 = 9;
const I8_BITS: u8 = 8;
const CRC_BITS: u8 = 32;
const OP_REPEAT: u8 = 0x1b;
const OP_ZEROS: u8 = 0x1c;
const OP_SHORT_DATA: u8 = 0x1d;
const OP_END: u8 = 0x1e;
const BLOCK_BYTES: usize = 8;
const I2_RING_BYTES: usize = 2 * (1 << I2_BITS);
const I4_RING_BYTES: usize = 4 * (1 << I4_BITS);
const I8_RING_BYTES: usize = 8 * (1 << I8_BITS);
const MAX_REPEAT_BLOCKS: usize = 1 << REPEAT_BITS;

#[derive(Copy, Clone)]
enum Op { D2, D4, D8, I2, I4, I8, N0 }

const TEMPLATES: [([Op; 4], u8); 26] = [
    ([Op::I8, Op::N0, Op::N0, Op::N0], 0x19), ([Op::I4, Op::I4, Op::N0, Op::N0], 0x18),
    ([Op::I4, Op::I2, Op::I2, Op::N0], 0x17), ([Op::I2, Op::I2, Op::I4, Op::N0], 0x13),
    ([Op::I2, Op::I2, Op::I2, Op::I2], 0x12), ([Op::I4, Op::I2, Op::D2, Op::N0], 0x16),
    ([Op::I4, Op::D2, Op::I2, Op::N0], 0x15), ([Op::I2, Op::D2, Op::I4, Op::N0], 0x0e),
    ([Op::D2, Op::I2, Op::I4, Op::N0], 0x09), ([Op::I2, Op::I2, Op::I2, Op::D2], 0x11),
    ([Op::I2, Op::I2, Op::D2, Op::I2], 0x10), ([Op::I2, Op::D2, Op::I2, Op::I2], 0x0d),
    ([Op::D2, Op::I2, Op::I2, Op::I2], 0x08), ([Op::I4, Op::D4, Op::N0, Op::N0], 0x14),
    ([Op::D4, Op::I4, Op::N0, Op::N0], 0x04), ([Op::I2, Op::I2, Op::D4, Op::N0], 0x0f),
    ([Op::I2, Op::D2, Op::I2, Op::D2], 0x0c), ([Op::I2, Op::D4, Op::I2, Op::N0], 0x0b),
    ([Op::D2, Op::I2, Op::I2, Op::D2], 0x07), ([Op::D2, Op::I2, Op::D2, Op::I2], 0x06),
    ([Op::D4, Op::I2, Op::I2, Op::N0], 0x03), ([Op::I2, Op::D2, Op::D4, Op::N0], 0x0a),
    ([Op::D2, Op::I2, Op::D4, Op::N0], 0x05), ([Op::D4, Op::I2, Op::D2, Op::N0], 0x02),
    ([Op::D4, Op::D2, Op::I2, Op::N0], 0x01), ([Op::D8, Op::N0, Op::N0, Op::N0], 0x00),
];

const DECOMP_OPS: [[Op; 4]; 26] = [
    [Op::D8, Op::N0, Op::N0, Op::N0], [Op::D4, Op::D2, Op::I2, Op::N0], [Op::D4, Op::I2, Op::D2, Op::N0],
    [Op::D4, Op::I2, Op::I2, Op::N0], [Op::D4, Op::I4, Op::N0, Op::N0], [Op::D2, Op::I2, Op::D4, Op::N0],
    [Op::D2, Op::I2, Op::D2, Op::I2], [Op::D2, Op::I2, Op::I2, Op::D2], [Op::D2, Op::I2, Op::I2, Op::I2],
    [Op::D2, Op::I2, Op::I4, Op::N0], [Op::I2, Op::D2, Op::D4, Op::N0], [Op::I2, Op::D4, Op::I2, Op::N0],
    [Op::I2, Op::D2, Op::I2, Op::D2], [Op::I2, Op::D2, Op::I2, Op::I2], [Op::I2, Op::D2, Op::I4, Op::N0],
    [Op::I2, Op::I2, Op::D4, Op::N0], [Op::I2, Op::I2, Op::D2, Op::I2], [Op::I2, Op::I2, Op::I2, Op::D2],
    [Op::I2, Op::I2, Op::I2, Op::I2], [Op::I2, Op::I2, Op::I4, Op::N0], [Op::I4, Op::D4, Op::N0, Op::N0],
    [Op::I4, Op::D2, Op::I2, Op::N0], [Op::I4, Op::I2, Op::D2, Op::N0], [Op::I4, Op::I2, Op::I2, Op::N0],
    [Op::I4, Op::I4, Op::N0, Op::N0], [Op::I8, Op::N0, Op::N0, Op::N0],
];

struct BitWriter { bytes: Vec<u8>, used: u8 }
impl BitWriter {
    fn new(capacity: usize) -> Self { Self { bytes: Vec::with_capacity(capacity), used: 0 } }
    fn put(&mut self, value: u64, bits: u8) {
        for shift in (0..bits).rev() {
            if self.used == 0 { self.bytes.push(0); }
            let bit = ((value >> shift) & 1) as u8;
            let byte = self.bytes.last_mut().expect("bit writer byte");
            *byte |= bit << (7 - self.used);
            self.used = (self.used + 1) % 8;
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.used != 0 { self.used = 0; }
        let aligned = (self.bytes.len() + (BLOCK_BYTES - 1)) & !(BLOCK_BYTES - 1);
        self.bytes.resize(aligned, 0);
        self.bytes
    }
}

struct BitReader<'a> { bytes: &'a [u8], offset: usize }
impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, bits: u8) -> KResult<u64> {
        if self.offset.checked_add(bits as usize).filter(|end| *end <= self.bytes.len() * 8).is_none() { return Err(BlockError::Eio); }
        let mut value = 0;
        for _ in 0..bits {
            let byte = self.bytes[self.offset / 8];
            value = (value << 1) | u64::from((byte >> (7 - self.offset % 8)) & 1);
            self.offset += 1;
        }
        Ok(value)
    }
}

fn crc32_be(data: &[u8]) -> u32 {
    let mut crc = 0u32;
    for byte in data { crc ^= u32::from(*byte) << 24; for _ in 0..8 { crc = if crc & (1 << 31) != 0 { (crc << 1) ^ 0x04c1_1db7 } else { crc << 1 }; } }
    crc
}

fn op_bytes(op: Op) -> usize { match op { Op::D2 | Op::I2 => 2, Op::D4 | Op::I4 => 4, Op::D8 | Op::I8 => 8, Op::N0 => 0 } }
fn is_index(op: Op) -> bool { matches!(op, Op::I2 | Op::I4 | Op::I8) }
fn index_bits(op: Op) -> u8 { match op { Op::I2 => I2_BITS, Op::I4 => I4_BITS, Op::I8 => I8_BITS, _ => 0 } }
fn ring_bytes(op: Op) -> usize { match op { Op::I2 => I2_RING_BYTES, Op::I4 => I4_RING_BYTES, Op::I8 => I8_RING_BYTES, _ => 0 } }

fn find_index(input: &[u8], current: usize, at: usize, op: Op) -> Option<usize> {
    let size = op_bytes(op); let ring = ring_bytes(op); let first = current.saturating_sub(ring);
    let needle = input.get(current + at..current + at + size)?;
    let mut pos = current.checked_sub(size)?;
    loop {
        if pos >= first && input[pos..pos + size] == *needle { return Some((pos / size) % (ring / size)); }
        if pos < size || pos - size < first { break; }
        pos -= size;
    }
    None
}

fn write_template(out: &mut BitWriter, input: &[u8], current: usize, template: ([Op; 4], u8)) -> bool {
    let (ops, code) = template; let mut at = 0; let mut indices = [0usize; 4];
    for (slot, op) in ops.iter().copied().enumerate() {
        if is_index(op) { let Some(index) = find_index(input, current, at, op) else { return false }; indices[slot] = index; }
        at += op_bytes(op);
    }
    out.put(u64::from(code), OP_BITS); at = 0;
    for (slot, op) in ops.iter().copied().enumerate() {
        let size = op_bytes(op);
        if is_index(op) { out.put(indices[slot] as u64, index_bits(op)); }
        else if size != 0 { let mut data = 0u64; for byte in &input[current + at..current + at + size] { data = (data << 8) | u64::from(*byte); } out.put(data, (size * 8) as u8); }
        at += size;
    }
    true
}

/// Encode one standard Linux software-842 stream. # C: O(page bytes * templates)
pub(super) fn compress(input: &[u8]) -> KResult<Vec<u8>> {
    let mut out = BitWriter::new(input.len() * 2 + BLOCK_BYTES); let mut pos = 0;
    while pos + BLOCK_BYTES <= input.len() {
        let block = &input[pos..pos + BLOCK_BYTES];
        if pos >= BLOCK_BYTES && block == &input[pos - BLOCK_BYTES..pos] {
            let mut count = 1;
            while count < MAX_REPEAT_BLOCKS && pos + (count + 1) * BLOCK_BYTES <= input.len()
                && input[pos + count * BLOCK_BYTES..pos + (count + 1) * BLOCK_BYTES] == *block { count += 1; }
            out.put(u64::from(OP_REPEAT), OP_BITS); out.put((count - 1) as u64, REPEAT_BITS); pos += count * BLOCK_BYTES; continue;
        }
        if block.iter().all(|byte| *byte == 0) { out.put(u64::from(OP_ZEROS), OP_BITS); pos += BLOCK_BYTES; continue; }
        let mut written = false;
        for template in TEMPLATES { if write_template(&mut out, input, pos, template) { written = true; break; } }
        if !written { return Err(BlockError::Eio); }
        pos += BLOCK_BYTES;
    }
    if pos != input.len() { let tail = &input[pos..]; out.put(u64::from(OP_SHORT_DATA), OP_BITS); out.put(tail.len() as u64, SHORT_DATA_BITS); for byte in tail { out.put(u64::from(*byte), 8); } }
    out.put(u64::from(OP_END), OP_BITS); out.put(u64::from(crc32_be(input)), CRC_BITS);
    Ok(out.finish())
}

fn copy_index(out: &mut [u8], written: &mut usize, index: usize, size: usize, ring: usize) -> KResult<()> {
    if *written + size > out.len() { return Err(BlockError::Eio); }
    let total = *written & !(BLOCK_BYTES - 1); let mut offset = index * size;
    if total > ring { let mut section = total & !(ring - 1); if offset >= total - section { section = section.checked_sub(ring).ok_or(BlockError::Eio)?; } offset += section; }
    if offset + size > total { return Err(BlockError::Eio); }
    out.copy_within(offset..offset + size, *written); *written += size; Ok(())
}

fn decode_op(reader: &mut BitReader<'_>, out: &mut [u8], written: &mut usize, op: Op) -> KResult<()> {
    let size = op_bytes(op); if *written + size > out.len() { return Err(BlockError::Eio); }
    if is_index(op) { return copy_index(out, written, reader.take(index_bits(op))? as usize, size, ring_bytes(op)); }
    if size != 0 { for slot in &mut out[*written..*written + size] { *slot = reader.take(8)? as u8; } *written += size; }
    Ok(())
}

/// Decode one standard Linux software-842 stream and require one full page. # C: O(page bytes)
pub(super) fn decompress(input: &[u8], out: &mut [u8]) -> KResult<()> {
    let mut reader = BitReader::new(input); let mut written = 0;
    loop {
        let code = reader.take(OP_BITS)? as u8;
        match code {
            OP_REPEAT => { let count = reader.take(REPEAT_BITS)? as usize + 1; if written < BLOCK_BYTES { return Err(BlockError::Eio); } for _ in 0..count { let start = written - BLOCK_BYTES; if written + BLOCK_BYTES > out.len() { return Err(BlockError::Eio); } out.copy_within(start..written, written); written += BLOCK_BYTES; } }
            OP_ZEROS => { if written + BLOCK_BYTES > out.len() { return Err(BlockError::Eio); } out[written..written + BLOCK_BYTES].fill(0); written += BLOCK_BYTES; }
            OP_SHORT_DATA => { let count = reader.take(SHORT_DATA_BITS)? as usize; if count == 0 || written + count > out.len() { return Err(BlockError::Eio); } for slot in &mut out[written..written + count] { *slot = reader.take(8)? as u8; } written += count; }
            OP_END => break,
            code if usize::from(code) < DECOMP_OPS.len() => for op in DECOMP_OPS[usize::from(code)] { decode_op(&mut reader, out, &mut written, op)?; },
            _ => return Err(BlockError::Eio),
        }
    }
    let crc = reader.take(CRC_BITS)? as u32;
    if written != out.len() || crc != crc32_be(out) { return Err(BlockError::Eio); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    const PAGE: usize = 4096;
    fn roundtrip(mut page: Vec<u8>) {
        let expected = page.clone(); let packed = compress(&page).unwrap(); page.fill(0);
        decompress(&packed, &mut page).unwrap(); assert_eq!(page, expected);
    }
    #[test] fn roundtrips_literals() { roundtrip((0..PAGE).map(|i| i as u8).collect()); }
    #[test] fn roundtrips_zeros_and_repeats() { let mut page = vec![0; PAGE]; page[1024..2048].fill(0xa5); roundtrip(page); }
    #[test] fn rejects_bad_crc() { let page = vec![0x42; PAGE]; let mut packed = compress(&page).unwrap(); packed[0] ^= 1; assert_eq!(decompress(&packed, &mut vec![0; PAGE]), Err(BlockError::Eio)); }
}
