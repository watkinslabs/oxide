//! The nftables register file. Five 16-byte slots addressed either as whole
//! registers (`NFT_REG_1`..`NFT_REG_4`) or as sixteen 4-byte sub-registers
//! (`NFT_REG32_00`..`NFT_REG32_15`) laid over the same bytes.

use crate::nft_expr::limits::REG_BYTES;
use crate::nft_expr::uapi::{NFT_REG32_00, NFT_REG32_MAX, NFT_REG32_SIZE, NFT_REG_1,
                            NFT_REG_MAX, NFT_REG_SIZE};

/// Byte offset of a register, or `None` when the number addresses no storage.
/// # C: O(1)
pub fn reg_off(register: u32) -> Option<usize> {
    if (NFT_REG_1..=NFT_REG_MAX).contains(&register) {
        return Some(register as usize * NFT_REG_SIZE);
    }
    if (NFT_REG32_00..=NFT_REG32_MAX).contains(&register) {
        return Some(NFT_REG_SIZE + (register - NFT_REG32_00) as usize * NFT_REG32_SIZE);
    }
    None
}

/// Whether `len` bytes fit in the register file starting at `register`.
/// # C: O(1)
pub fn register_load_valid(register: u32, len: usize) -> bool {
    len != 0 && reg_off(register).is_some_and(|offset| offset + len <= REG_BYTES)
}

/// Working register file for one rule evaluation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Regs { data: [u8; REG_BYTES] }

impl Default for Regs {
    fn default() -> Self { Self::new() }
}

impl Regs {
    /// # C: O(1)
    pub fn new() -> Self { Self { data: [0u8; REG_BYTES] } }

    /// Raw view for callers that hand a whole register to a set lookup.
    /// # C: O(1)
    pub fn bytes(&self) -> &[u8] { &self.data }

    /// `len` bytes starting at `register`. # C: O(1)
    pub fn load(&self, register: u32, len: usize) -> Option<&[u8]> {
        let offset = reg_off(register)?;
        if offset + len > REG_BYTES { return None; }
        Some(&self.data[offset..offset + len])
    }

    /// Everything from `register` to the end of the file — the shape a set
    /// lookup consumes when the key width lives with the set. # C: O(1)
    pub fn tail(&self, register: u32) -> Option<&[u8]> {
        Some(&self.data[reg_off(register)?..])
    }

    /// Write `src` at `register`. # C: O(len)
    pub fn store(&mut self, register: u32, src: &[u8]) -> Option<()> {
        let offset = reg_off(register)?;
        if offset + src.len() > REG_BYTES { return None; }
        self.data[offset..offset + src.len()].copy_from_slice(src);
        Some(())
    }

    /// Write `src` and zero the remainder of its final 4-byte word, which is
    /// what makes a comparison against a padded literal well defined.
    /// # C: O(len)
    pub fn store_padded(&mut self, register: u32, src: &[u8]) -> Option<()> {
        let padded = (src.len() + NFT_REG32_SIZE - 1) / NFT_REG32_SIZE * NFT_REG32_SIZE;
        let offset = reg_off(register)?;
        if offset + padded > REG_BYTES { return None; }
        self.data[offset..offset + src.len()].copy_from_slice(src);
        self.data[offset + src.len()..offset + padded].fill(0);
        Some(())
    }

    /// Store a scalar in host order — how a numeric key lands in a register.
    /// # C: O(1)
    pub fn store_u8(&mut self, register: u32, value: u8) -> Option<()> {
        self.store_padded(register, &[value])
    }
    /// # C: O(1)
    pub fn store_u16(&mut self, register: u32, value: u16) -> Option<()> {
        self.store_padded(register, &value.to_ne_bytes())
    }
    /// # C: O(1)
    pub fn store_u32(&mut self, register: u32, value: u32) -> Option<()> {
        self.store(register, &value.to_ne_bytes())
    }
    /// # C: O(1)
    pub fn store_u64(&mut self, register: u32, value: u64) -> Option<()> {
        self.store(register, &value.to_ne_bytes())
    }
    /// Store a scalar in network order — how a header-shaped key lands.
    /// # C: O(1)
    pub fn store_be16(&mut self, register: u32, value: u16) -> Option<()> {
        self.store_padded(register, &value.to_be_bytes())
    }
    /// # C: O(1)
    pub fn store_be32(&mut self, register: u32, value: u32) -> Option<()> {
        self.store(register, &value.to_be_bytes())
    }

    /// Host-order scalar read. # C: O(1)
    pub fn load_u32(&self, register: u32) -> Option<u32> {
        let b = self.load(register, 4)?;
        Some(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// # C: O(1)
    pub fn load_u8(&self, register: u32) -> Option<u8> {
        self.load(register, 1).map(|b| b[0])
    }
    /// Network-order scalar read — a port taken from a register. # C: O(1)
    pub fn load_be16(&self, register: u32) -> Option<u16> {
        let b = self.load(register, 2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    /// # C: O(1)
    pub fn load_be32(&self, register: u32) -> Option<u32> {
        let b = self.load(register, 4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Copy a fixed 16-byte address out of a register. # C: O(1)
    pub fn load_addr16(&self, register: u32) -> Option<[u8; 16]> {
        let b = self.load(register, 16)?;
        let mut out = [0u8; 16];
        out.copy_from_slice(b);
        Some(out)
    }
}
