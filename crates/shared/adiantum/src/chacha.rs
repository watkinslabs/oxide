//! The ChaCha permutation, its keystream, and the extended-nonce construction
//! built on top of it.
//!
//! The round count is a plain argument rather than a type parameter so a single
//! monomorphisation serves both the twelve-round stream cipher the encryption
//! mode uses and the twenty-round variant the published vectors pin.

/// Bytes per keystream block.
pub const CHACHA_BLOCK_LEN: usize = 64;
/// Key width, in bytes.
pub const CHACHA_KEY_LEN: usize = 32;
/// Nonce width of the base construction, in bytes.
pub const CHACHA_IV_LEN: usize = 16;
/// Nonce-plus-stream-position width of the extended-nonce construction.
pub const XCHACHA_IV_LEN: usize = 32;
/// Words in a state matrix.
pub const STATE_WORDS: usize = 16;
/// Words the abbreviated core emits.
pub const HCHACHA_OUT_WORDS: usize = 8;

/// Round count of the twelve-round variant.
pub const ROUNDS_12: u32 = 12;
/// Round count of the twenty-round variant.
pub const ROUNDS_20: u32 = 20;

/// The four constant words that open every state matrix, "expand 32-byte k".
const CONSTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Offset of the block counter within the state matrix.
const COUNTER_WORD: usize = 12;

/// A state matrix: four constant words, eight key words, four nonce/counter
/// words.
#[derive(Clone)]
pub struct State { pub x: [u32; STATE_WORDS] }

/// Read a little-endian word out of a byte slice at a word index.
fn le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])
}

impl State {
    /// Build a state from key bytes and a nonce.
    ///
    /// # C: consts || le32(key) || le32(iv)
    pub fn new(key: &[u8; CHACHA_KEY_LEN], iv: &[u8; CHACHA_IV_LEN]) -> Self {
        let mut key_words = [0u32; 8];
        for i in 0..8 { key_words[i] = le32(key, i); }
        Self::from_key_words(&key_words, iv)
    }

    /// Build a state from key words already in host order.
    ///
    /// The abbreviated core emits words, not bytes, and the extended-nonce
    /// construction feeds those words straight back in as the subkey.
    ///
    /// # C: consts || key_words || le32(iv)
    pub fn from_key_words(key_words: &[u32; 8], iv: &[u8; CHACHA_IV_LEN]) -> Self {
        let mut x = [0u32; STATE_WORDS];
        x[0..4].copy_from_slice(&CONSTS);
        x[4..12].copy_from_slice(key_words);
        for i in 0..4 { x[12 + i] = le32(iv, i); }
        State { x }
    }
}

/// The permutation: `rounds / 2` double rounds over the state matrix.
///
/// # C: (column round; diagonal round)^(rounds/2)
fn permute(x: &mut [u32; STATE_WORDS], rounds: u32) {
    let mut i = 0;
    while i < rounds {
        quarter(x, 0, 4, 8, 12); quarter(x, 1, 5, 9, 13);
        quarter(x, 2, 6, 10, 14); quarter(x, 3, 7, 11, 15);
        quarter(x, 0, 5, 10, 15); quarter(x, 1, 6, 11, 12);
        quarter(x, 2, 7, 8, 13); quarter(x, 3, 4, 9, 14);
        i += 2;
    }
}

/// One quarter round over four state words.
fn quarter(x: &mut [u32; STATE_WORDS], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]); x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]); x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]); x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]); x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// Produce one keystream block and advance the block counter.
///
/// # C: out = le32(permute(state) + state); state[12] += 1
pub fn block(state: &mut State, out: &mut [u8; CHACHA_BLOCK_LEN], rounds: u32) {
    let mut p = state.x;
    permute(&mut p, rounds);
    for i in 0..STATE_WORDS {
        let w = p[i].wrapping_add(state.x[i]);
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    state.x[COUNTER_WORD] = state.x[COUNTER_WORD].wrapping_add(1);
}

/// The abbreviated core: permute, then emit words 0..4 and 12..16 without the
/// feed-forward addition.
///
/// # C: permute(consts || key || nonce)[0..4, 12..16]
pub fn hchacha(key: &[u8; CHACHA_KEY_LEN], nonce: &[u8; CHACHA_IV_LEN], rounds: u32)
    -> [u32; HCHACHA_OUT_WORDS]
{
    let st = State::new(key, nonce);
    let mut p = st.x;
    permute(&mut p, rounds);
    let mut out = [0u32; HCHACHA_OUT_WORDS];
    out[0..4].copy_from_slice(&p[0..4]);
    out[4..8].copy_from_slice(&p[12..16]);
    out
}

/// Exclusive-or the keystream of `state` over `buf` in place.
///
/// # C: buf[i] ^= keystream(state)[i]
pub fn xor_stream(state: &mut State, buf: &mut [u8], rounds: u32) {
    let mut ks = [0u8; CHACHA_BLOCK_LEN];
    let mut off = 0;
    while off < buf.len() {
        block(state, &mut ks, rounds);
        let n = core::cmp::min(CHACHA_BLOCK_LEN, buf.len() - off);
        for i in 0..n { buf[off + i] ^= ks[i]; }
        off += n;
    }
}

/// Exclusive-or the extended-nonce keystream over `buf` in place.
///
/// The 32-byte input splits as a 24-byte nonce followed by an 8-byte stream
/// position. The first 16 nonce bytes derive a subkey through the abbreviated
/// core; the base construction then runs with a nonce built as stream position
/// followed by the remaining 8 nonce bytes.
///
/// # C: buf ^= chacha(hchacha(key, iv[0..16]), iv[24..32] || iv[16..24])
pub fn xchacha_xor(key: &[u8; CHACHA_KEY_LEN], iv: &[u8; XCHACHA_IV_LEN],
                   buf: &mut [u8], rounds: u32)
{
    let mut n16 = [0u8; CHACHA_IV_LEN];
    n16.copy_from_slice(&iv[0..16]);
    let subkey = hchacha(key, &n16, rounds);

    let mut real_iv = [0u8; CHACHA_IV_LEN];
    real_iv[0..8].copy_from_slice(&iv[24..32]);
    real_iv[8..16].copy_from_slice(&iv[16..24]);

    let mut st = State::from_key_words(&subkey, &real_iv);
    xor_stream(&mut st, buf, rounds);
}
