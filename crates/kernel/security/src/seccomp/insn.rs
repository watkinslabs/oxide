// Classic-BPF instruction encoding + the `seccomp_data` the filter reads.
// Opcode numbers are the fixed cBPF ABI; no policy here.

use super::uapi::SECCOMP_DATA_BYTES;

/// `BPF_CLASS(code) = code & 0x07`.
pub const BPF_CLASS_MASK: u16 = 0x07;
pub const BPF_LD:   u16 = 0x00;
pub const BPF_LDX:  u16 = 0x01;
pub const BPF_ST:   u16 = 0x02;
pub const BPF_STX:  u16 = 0x03;
pub const BPF_ALU:  u16 = 0x04;
pub const BPF_JMP:  u16 = 0x05;
pub const BPF_RET:  u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;

/// `BPF_SIZE(code) = code & 0x18`.
pub const BPF_SIZE_MASK: u16 = 0x18;
pub const BPF_W: u16 = 0x00;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;

/// `BPF_MODE(code) = code & 0xe0`.
pub const BPF_MODE_MASK: u16 = 0xe0;
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;

/// `BPF_OP(code) = code & 0xf0`.
pub const BPF_OP_MASK: u16 = 0xf0;
pub const BPF_ADD: u16 = 0x00;
pub const BPF_SUB: u16 = 0x10;
pub const BPF_MUL: u16 = 0x20;
pub const BPF_DIV: u16 = 0x30;
pub const BPF_OR:  u16 = 0x40;
pub const BPF_AND: u16 = 0x50;
pub const BPF_LSH: u16 = 0x60;
pub const BPF_RSH: u16 = 0x70;
pub const BPF_NEG: u16 = 0x80;
pub const BPF_MOD: u16 = 0x90;
pub const BPF_XOR: u16 = 0xa0;

pub const BPF_JA:   u16 = 0x00;
pub const BPF_JEQ:  u16 = 0x10;
pub const BPF_JGT:  u16 = 0x20;
pub const BPF_JGE:  u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;

/// `BPF_SRC(code) = code & 0x08` for ALU/JMP.
pub const BPF_SRC_MASK: u16 = 0x08;
pub const BPF_K: u16 = 0x00;
pub const BPF_X: u16 = 0x08;

/// `BPF_RVAL(code) = code & 0x18` for `BPF_RET` — a DIFFERENT mask from
/// `BPF_SRC`. `BPF_RET|BPF_A` is 0x16, and `0x16 & BPF_SRC_MASK == 0`, so
/// selecting the return source with the SRC mask silently turns
/// `return A` into `return k` (usually 0 = `SECCOMP_RET_KILL_THREAD`).
pub const BPF_RVAL_MASK: u16 = 0x18;
pub const BPF_A: u16 = 0x10;

/// `BPF_MISCOP(code) = code & 0xf8`.
pub const BPF_MISCOP_MASK: u16 = 0xf8;
pub const BPF_TAX: u16 = 0x00;
pub const BPF_TXA: u16 = 0x80;

/// `struct sock_filter` — 8 bytes. Packed 1-per-u64 in the per-task filter
/// buffer so a chain is a plain `Vec<Vec<u64>>` with no pointer chasing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SockFilter {
    pub code: u16,
    pub jt:   u8,
    pub jf:   u8,
    pub k:    u32,
}

impl SockFilter {
    /// # C: O(1)
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self { Self { code, jt, jf, k } }
    /// # C: O(1)
    pub const fn encode(self) -> u64 {
        (self.code as u64) | ((self.jt as u64) << 16) | ((self.jf as u64) << 24) | ((self.k as u64) << 32)
    }
    /// # C: O(1)
    pub const fn decode(w: u64) -> Self {
        Self { code: (w & 0xFFFF) as u16, jt: ((w >> 16) & 0xFF) as u8,
               jf: ((w >> 24) & 0xFF) as u8, k: (w >> 32) as u32 }
    }
}

/// `struct seccomp_data` — 64 bytes, read by
/// `BPF_LD|BPF_W|BPF_ABS` at 4-byte-aligned offsets:
///   0  nr (i32) | 4 arch (u32) | 8 instruction_pointer (u64) | 16 args[6]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SeccompData {
    pub nr:   i32,
    pub arch: u32,
    pub ip:   u64,
    pub args: [u64; 6],
}

impl SeccompData {
    /// Host-order byte image of the struct, built ONCE per filter run so the
    /// per-instruction `BPF_LD|BPF_W|BPF_ABS` load is a 4-byte slice read
    /// rather than a 64-byte rebuild. `to_ne_bytes` keeps it endian-correct
    /// without a `transmute`.
    /// # C: O(1) — 64 bytes
    pub fn bytes(&self) -> [u8; SECCOMP_DATA_BYTES as usize] {
        let mut b = [0u8; SECCOMP_DATA_BYTES as usize];
        b[0..4].copy_from_slice(&self.nr.to_ne_bytes());
        b[4..8].copy_from_slice(&self.arch.to_ne_bytes());
        b[8..16].copy_from_slice(&self.ip.to_ne_bytes());
        for i in 0..6 { b[16 + i * 8..24 + i * 8].copy_from_slice(&self.args[i].to_ne_bytes()); }
        b
    }
}

/// Load the 32-bit word at byte offset `off` of a `seccomp_data` image.
/// `seccomp_check_filter` already rejected unaligned / out-of-range offsets
/// at install time, so an out-of-range read here can only come from an
/// unverified program; it reads 0 rather than walking off the struct.
/// # C: O(1)
pub fn data_word(b: &[u8; SECCOMP_DATA_BYTES as usize], off: u32) -> u32 {
    if off % 4 != 0 || off.saturating_add(4) > SECCOMP_DATA_BYTES { return 0; }
    let o = off as usize;
    u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
