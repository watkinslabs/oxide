// Cipher-block chaining, and the ciphertext-stealing variant that lets a
// message keep its exact length.
//
// Plain CBC handles only whole blocks. The stealing variant (CS3, the
// convention RFC 3962 fixes and the one filesystem name encryption uses)
// takes any length from one block upward and returns exactly that many bytes.
//
// Three details decide whether two implementations agree, and none of them is
// visible to a round-trip against oneself:
//
// - CS3 swaps the LAST TWO ciphertext blocks. The unswapped variant (CS2/CS1)
//   decrypts correctly under its own encryptor and not under anyone else's.
// - The swap happens even when the length is an exact multiple of the block
//   size. Skipping it there is the single most common divergence.
// - A message of exactly one block is plain CBC, with no swap and no steal.

use crate::cipher::{blk, xor, BlockCipher, BLOCK_LEN};

/// Why a mode refused the buffer it was given.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CbcError {
    /// Plain CBC was handed a length that is not a whole number of blocks.
    NotBlockAligned,
    /// Ciphertext stealing was handed less than one block, which it cannot
    /// steal from.
    TooShort,
}

/// CBC-encrypt `buf` in place, leaving `iv` holding the last ciphertext block
/// so a caller can continue the chain.
/// # C: O(len(buf))
pub fn encrypt<C: BlockCipher>(key: &C, iv: &mut [u8; BLOCK_LEN], buf: &mut [u8])
    -> Result<(), CbcError>
{
    if !buf.len().is_multiple_of(BLOCK_LEN) { return Err(CbcError::NotBlockAligned); }
    let mut chain = *iv;
    for c in buf.chunks_exact_mut(BLOCK_LEN) {
        xor(c, &chain);
        let mut b = blk(c);
        key.encrypt_block(&mut b);
        c.copy_from_slice(&b);
        chain = b;
    }
    *iv = chain;
    Ok(())
}

/// CBC-decrypt `buf` in place, leaving `iv` holding the last ciphertext block
/// that was consumed.
/// # C: O(len(buf))
pub fn decrypt<C: BlockCipher>(key: &C, iv: &mut [u8; BLOCK_LEN], buf: &mut [u8])
    -> Result<(), CbcError>
{
    if !buf.len().is_multiple_of(BLOCK_LEN) { return Err(CbcError::NotBlockAligned); }
    let mut chain = *iv;
    for c in buf.chunks_exact_mut(BLOCK_LEN) {
        let ct = blk(c);
        let mut b = ct;
        key.decrypt_block(&mut b);
        xor(&mut b, &chain);
        c.copy_from_slice(&b);
        chain = ct;
    }
    *iv = chain;
    Ok(())
}

/// CBC with ciphertext stealing (CS3), in place, for any length of at least
/// one block.
/// # C: O(len(buf))
pub fn cts_encrypt<C: BlockCipher>(key: &C, iv: &[u8; BLOCK_LEN], buf: &mut [u8])
    -> Result<(), CbcError>
{
    let n = buf.len();
    if n < BLOCK_LEN { return Err(CbcError::TooShort); }
    let mut chain = *iv;
    if n == BLOCK_LEN { return encrypt(key, &mut chain, buf); }
    // Everything but the tail is ordinary CBC. The tail is whatever the last
    // whole block boundary below the final byte leaves over — a full block
    // when the length divides evenly, which is why the swap still happens.
    let head = ((n - 1) / BLOCK_LEN) * BLOCK_LEN;
    let tail = n - head;
    encrypt(key, &mut chain, &mut buf[..head])?;
    // `chain` is now C(n-1). Encrypt the zero-extended final plaintext under
    // it; that block becomes the last FULL block of output, and the head of
    // C(n-1) is what remains as the short tail.
    let prev = blk(&buf[head - BLOCK_LEN..head]);
    let mut last = [0u8; BLOCK_LEN];
    last[..tail].copy_from_slice(&buf[head..]);
    xor(&mut last, &chain);
    key.encrypt_block(&mut last);
    buf[head..].copy_from_slice(&prev[..tail]);
    buf[head - BLOCK_LEN..head].copy_from_slice(&last);
    Ok(())
}

/// The inverse of [`cts_encrypt`].
/// # C: O(len(buf))
pub fn cts_decrypt<C: BlockCipher>(key: &C, iv: &[u8; BLOCK_LEN], buf: &mut [u8])
    -> Result<(), CbcError>
{
    let n = buf.len();
    if n < BLOCK_LEN { return Err(CbcError::TooShort); }
    let mut chain = *iv;
    if n == BLOCK_LEN { return decrypt(key, &mut chain, buf); }
    let head = ((n - 1) / BLOCK_LEN) * BLOCK_LEN;
    let tail = n - head;
    // The block the final full block chains against: the one before it, or
    // the IV when the final full block is the first.
    let space: [u8; BLOCK_LEN] = if head <= BLOCK_LEN {
        *iv
    } else {
        blk(&buf[head - 2 * BLOCK_LEN..head - BLOCK_LEN])
    };
    // Undo the swap first: recover the full C(n-1) from its stolen head plus
    // the bytes the last block's raw decryption supplies.
    let mut dn = blk(&buf[head - BLOCK_LEN..head]);
    key.decrypt_block(&mut dn);
    let mut cn1 = [0u8; BLOCK_LEN];
    cn1[..tail].copy_from_slice(&buf[head..]);
    cn1[tail..].copy_from_slice(&dn[tail..]);
    // The final plaintext is the stolen head XOR the raw decryption.
    let mut pn = dn;
    xor(&mut pn[..tail], &buf[head..]);
    buf[head..].copy_from_slice(&pn[..tail]);
    buf[head - BLOCK_LEN..head].copy_from_slice(&cn1);
    decrypt(key, &mut chain, &mut buf[..head - BLOCK_LEN])?;
    let mut last_iv = space;
    decrypt(key, &mut last_iv, &mut buf[head - BLOCK_LEN..head])?;
    Ok(())
}
