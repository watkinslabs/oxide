// What a mode needs from the cipher underneath it.
//
// The width is FIXED at 128 bits rather than made an associated constant. Both
// ciphers a filesystem names are 128-bit, XTS's tweak arithmetic is defined
// over GF(2^128) specifically, and a width-generic buffer type would put every
// mode behind const generics for no reachable second width. When one arrives
// the constant is the single place that has to move.

/// Bytes per block, for every cipher this crate's modes accept.
pub const BLOCK_LEN: usize = 16;

/// A 128-bit block cipher, keyed.
///
/// `from_key` takes bytes rather than a fixed-width array because the modes
/// above split a caller's key buffer themselves — XTS halves it — and cannot
/// know which of a cipher's widths the halves land on. A width the cipher does
/// not accept is `None`, never a silently truncated or padded key.
pub trait BlockCipher: Sized + Clone {
    /// Expand `key`, or `None` when the cipher has no such key width.
    /// # C: O(key schedule)
    fn from_key(key: &[u8]) -> Option<Self>;

    /// Encrypt one block in place.
    /// # C: O(1)
    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]);

    /// Decrypt one block in place.
    /// # C: O(1)
    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]);
}

/// `a ^= b`, over the shorter of the two. # C: O(len)
pub(crate) fn xor(a: &mut [u8], b: &[u8]) { for i in 0..a.len().min(b.len()) { a[i] ^= b[i]; } }

/// Read one block out of a slice, which must hold at least a block.
/// # C: O(1)
pub(crate) fn blk(s: &[u8]) -> [u8; BLOCK_LEN] {
    let mut b = [0u8; BLOCK_LEN];
    b.copy_from_slice(&s[..BLOCK_LEN]);
    b
}
