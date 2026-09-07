//! MD4 message digest over the context record the native surface exposes.

/// Bytes one compression block consumes.
pub(crate) const BLOCK_BYTES: usize = 64;
/// Words one compression block holds.
const BLOCK_WORDS: usize = 16;
/// Chaining words the context carries.
pub(crate) const STATE_WORDS: usize = 4;
/// Bytes the produced digest occupies.
pub(crate) const DIGEST_BYTES: usize = 16;
/// Context record layout: chaining state, bit count, block, digest.
pub(crate) const CONTEXT_BYTES: usize = STATE_WORDS * 4 + 8 + BLOCK_BYTES + DIGEST_BYTES;
const STATE_INIT: [u32; STATE_WORDS] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
const ROUND_TWO_CONSTANT: u32 = 0x5a82_7999;
const ROUND_THREE_CONSTANT: u32 = 0x6ed9_eba1;
const ROUND_ONE_SHIFTS: [u32; 4] = [3, 7, 11, 19];
const ROUND_TWO_SHIFTS: [u32; 4] = [3, 5, 9, 13];
const ROUND_THREE_SHIFTS: [u32; 4] = [3, 9, 11, 15];
const ROUND_TWO_ORDER: [usize; BLOCK_WORDS] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
const ROUND_THREE_ORDER: [usize; BLOCK_WORDS] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
/// Byte count that still leaves room for the length field.
const LENGTH_FIELD_BYTES: usize = 8;

/// Accumulator state: the chaining words, the bit counter, and the partial
/// block, in the order the exported context record carries them.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Context {
    pub state: [u32; STATE_WORDS],
    pub count: [u32; 2],
    pub block: [u8; BLOCK_BYTES],
    pub digest: [u8; DIGEST_BYTES],
}

impl Context {
    /// # C: O(1)
    pub(crate) fn new() -> Self { Context { state: STATE_INIT, count: [0, 0], block: [0; BLOCK_BYTES], digest: [0; DIGEST_BYTES] } }

    /// # C: O(context bytes)
    pub(crate) fn decode(raw: &[u8; CONTEXT_BYTES]) -> Self {
        let mut out = Context { state: [0; STATE_WORDS], count: [0, 0], block: [0; BLOCK_BYTES], digest: [0; DIGEST_BYTES] };
        for (index, slot) in out.state.iter_mut().enumerate() { *slot = u32::from_le_bytes(raw[index * 4..index * 4 + 4].try_into().unwrap()); }
        for (index, slot) in out.count.iter_mut().enumerate() { *slot = u32::from_le_bytes(raw[16 + index * 4..20 + index * 4].try_into().unwrap()); }
        out.block.copy_from_slice(&raw[24..24 + BLOCK_BYTES]);
        out.digest.copy_from_slice(&raw[24 + BLOCK_BYTES..CONTEXT_BYTES]);
        out
    }

    /// # C: O(context bytes)
    pub(crate) fn encode(&self) -> [u8; CONTEXT_BYTES] {
        let mut raw = [0u8; CONTEXT_BYTES];
        for (index, word) in self.state.iter().enumerate() { raw[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes()); }
        for (index, word) in self.count.iter().enumerate() { raw[16 + index * 4..20 + index * 4].copy_from_slice(&word.to_le_bytes()); }
        raw[24..24 + BLOCK_BYTES].copy_from_slice(&self.block);
        raw[24 + BLOCK_BYTES..CONTEXT_BYTES].copy_from_slice(&self.digest);
        raw
    }

    /// Absorb one message run, carrying the bit count as the reference does.
    /// # C: O(message bytes)
    pub(crate) fn update(&mut self, message: &[u8]) {
        let len = message.len() as u32;
        let previous = self.count[0];
        self.count[0] = previous.wrapping_add(len << 3);
        if self.count[0] < previous { self.count[1] = self.count[1].wrapping_add(1); }
        self.count[1] = self.count[1].wrapping_add(len >> 29);
        let held = ((previous >> 3) & 0x3f) as usize;
        let mut rest = message;
        if held != 0 {
            let wanted = BLOCK_BYTES - held;
            if rest.len() < wanted { self.block[held..held + rest.len()].copy_from_slice(rest); return; }
            let (head, tail) = rest.split_at(wanted);
            self.block[held..BLOCK_BYTES].copy_from_slice(head);
            self.compress();
            rest = tail;
        }
        while rest.len() >= BLOCK_BYTES {
            let (head, tail) = rest.split_at(BLOCK_BYTES);
            self.block.copy_from_slice(head);
            self.compress();
            rest = tail;
        }
        self.block[..rest.len()].copy_from_slice(rest);
    }

    /// Pad the held block and publish the digest, as the reference leaves it.
    /// # C: O(1)
    pub(crate) fn finish(&mut self) {
        let held = ((self.count[0] >> 3) & 0x3f) as usize;
        self.block[held] = 0x80;
        let pad = BLOCK_BYTES - 1 - held;
        if pad < LENGTH_FIELD_BYTES {
            for slot in &mut self.block[held + 1..BLOCK_BYTES] { *slot = 0; }
            self.compress();
            for slot in &mut self.block[..BLOCK_BYTES - LENGTH_FIELD_BYTES] { *slot = 0; }
        } else {
            for slot in &mut self.block[held + 1..BLOCK_BYTES - LENGTH_FIELD_BYTES] { *slot = 0; }
        }
        self.block[BLOCK_BYTES - LENGTH_FIELD_BYTES..BLOCK_BYTES - 4].copy_from_slice(&self.count[0].to_le_bytes());
        self.block[BLOCK_BYTES - 4..].copy_from_slice(&self.count[1].to_le_bytes());
        self.compress();
        for (index, word) in self.state.iter().enumerate() { self.digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes()); }
    }

    fn compress(&mut self) {
        let mut input = [0u32; BLOCK_WORDS];
        for (index, slot) in input.iter_mut().enumerate() { *slot = u32::from_le_bytes(self.block[index * 4..index * 4 + 4].try_into().unwrap()); }
        transform(&mut self.state, &input);
    }
}

fn transform(state: &mut [u32; STATE_WORDS], input: &[u32; BLOCK_WORDS]) {
    let mut work = *state;
    for round in 0..BLOCK_WORDS {
        let step = round % STATE_WORDS;
        let target = (STATE_WORDS - step) % STATE_WORDS;
        let (b, c, d) = triple(&work, target);
        let mixed = (b & c) | (!b & d);
        work[target] = work[target].wrapping_add(mixed).wrapping_add(input[round]).rotate_left(ROUND_ONE_SHIFTS[step]);
    }
    for round in 0..BLOCK_WORDS {
        let step = round % STATE_WORDS;
        let target = (STATE_WORDS - step) % STATE_WORDS;
        let (b, c, d) = triple(&work, target);
        let mixed = (b & c) | (b & d) | (c & d);
        work[target] = work[target].wrapping_add(mixed).wrapping_add(input[ROUND_TWO_ORDER[round]]).wrapping_add(ROUND_TWO_CONSTANT).rotate_left(ROUND_TWO_SHIFTS[step]);
    }
    for round in 0..BLOCK_WORDS {
        let step = round % STATE_WORDS;
        let target = (STATE_WORDS - step) % STATE_WORDS;
        let (b, c, d) = triple(&work, target);
        let mixed = b ^ c ^ d;
        work[target] = work[target].wrapping_add(mixed).wrapping_add(input[ROUND_THREE_ORDER[round]]).wrapping_add(ROUND_THREE_CONSTANT).rotate_left(ROUND_THREE_SHIFTS[step]);
    }
    for (index, word) in work.iter().enumerate() { state[index] = state[index].wrapping_add(*word); }
}

fn triple(work: &[u32; STATE_WORDS], target: usize) -> (u32, u32, u32) {
    (work[(target + 1) % STATE_WORDS], work[(target + 2) % STATE_WORDS], work[(target + 3) % STATE_WORDS])
}
