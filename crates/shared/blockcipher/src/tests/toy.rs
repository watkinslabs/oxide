//! A permutation standing in for a cipher, so the modes can be exercised
//! without pulling a cipher crate in as a dependency.
//!
//! It is a bijection and nothing more — it makes no security claim and is
//! reachable only from tests. What the mode tests need from it is that
//! different inputs give different outputs and that decrypt undoes encrypt;
//! whether the permutation is any good is the cipher crates' problem.

use crate::cipher::{BlockCipher, BLOCK_LEN};

/// Two key widths, so the key-splitting rules have a width to reject.
pub(crate) const TOY_KEY_LENS: [usize; 2] = [8, 16];

#[derive(Clone)]
pub(crate) struct Toy { k: [u8; BLOCK_LEN] }

impl BlockCipher for Toy {
    fn from_key(key: &[u8]) -> Option<Self> {
        if !TOY_KEY_LENS.contains(&key.len()) { return None; }
        // Short keys repeat to fill the block, which keeps the two widths
        // distinguishable without a schedule.
        let mut k = [0u8; BLOCK_LEN];
        for (i, b) in k.iter_mut().enumerate() { *b = key[i % key.len()] ^ (i as u8); }
        Some(Self { k })
    }

    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        for (i, b) in block.iter_mut().enumerate() { *b = b.wrapping_add(self.k[i]) ^ self.k[BLOCK_LEN - 1 - i]; }
        block.rotate_left(1);
    }

    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        block.rotate_right(1);
        for (i, b) in block.iter_mut().enumerate() { *b = (*b ^ self.k[BLOCK_LEN - 1 - i]).wrapping_sub(self.k[i]); }
    }
}

/// A key of the wider width, deterministic.
pub(crate) fn key(seed: u8) -> [u8; BLOCK_LEN] {
    let mut k = [0u8; BLOCK_LEN];
    for (i, b) in k.iter_mut().enumerate() { *b = seed.wrapping_mul(31).wrapping_add(i as u8); }
    k
}

/// `n` deterministic bytes of "plaintext".
pub(crate) fn data(n: usize) -> alloc::vec::Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(37).wrapping_add(11)).collect()
}

#[test]
fn the_stand_in_is_actually_a_permutation() {
    // If it were not, every mode test below would be measuring nothing.
    let c = Toy::from_key(&key(3)).expect("the wide width is accepted");
    let mut seen = alloc::vec::Vec::new();
    for i in 0..64u8 {
        let mut b = [i; BLOCK_LEN];
        let plain = b;
        c.encrypt_block(&mut b);
        assert!(!seen.contains(&b), "two inputs collided");
        seen.push(b);
        c.decrypt_block(&mut b);
        assert_eq!(b, plain, "decrypt undoes encrypt");
    }
    assert!(Toy::from_key(&[0u8; 7]).is_none(), "a width the cipher does not have is refused");
}
