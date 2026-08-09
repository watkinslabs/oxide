// `modify_ldt(2)` decision core (x86 UAPI).
//
// Deliberately NOT `#![cfg(target_os = "oxide-kernel")]`: the slot file
// `154_modify_ldt.rs` is kernel-only, so any rule written inside it is
// invisible to `cargo test`. Descriptor packing is a BIT LAYOUT — one wrong
// bit is a silent privilege bug (a DPL, a present flag, an expand-down data
// segment) that no boot notices — so the packing, the `user_desc` decode, the
// sub-function classification and the whole EINVAL ladder live here and are
// pinned by byte-exact tests.
//
// Module manifest:
//   this file           — UAPI constants, `user_desc` decode, func classification.
//   ldt_abi/desc.rs     — `desc_struct` packing (`fill_ldt`) + the empty-entry rules.
//   ldt_abi/write.rs    — `write_ldt` validation ladder and its errno order.
//   ldt_abi/read.rs     — `read_ldt` / `read_default_ldt` sizing rules.
//   ldt_abi/tests.rs    — hosted unit tests (manifest of test modules).

use syscall::errno::Errno;

pub mod desc;
pub mod read;
pub mod write;

pub use desc::{fill_ldt, ldt_empty, ldt_zero, DESC_BYTES};
pub use read::{ReadPlan, DEFAULT_LDT_BYTES};
pub use write::{validate_write, WriteEntry};

/// Maximum number of LDT entries a process may install (x86 UAPI
/// `LDT_ENTRIES`). The selector index field is 13 bits, so this is the
/// architectural ceiling, not a policy choice.
pub const LDT_ENTRIES: u32 = 8192;

/// Bytes per LDT entry (x86 UAPI `LDT_ENTRY_SIZE`) — one 8-byte segment
/// descriptor.
pub const LDT_ENTRY_SIZE: u32 = 8;

/// Bytes the whole table occupies when full. `read_ldt` clamps its
/// `bytecount` to this.
pub const LDT_TABLE_BYTES: u64 = LDT_ENTRIES as u64 * LDT_ENTRY_SIZE as u64;

/// `sizeof(struct user_desc)` — three `unsigned int` fields plus one
/// bitfield word. Fixed at 16 on both the 32- and 64-bit ABI; `write_ldt`
/// rejects any other `bytecount` with EINVAL before it touches the pointer.
pub const USER_DESC_BYTES: u64 = 16;

/// `contents` values (`MODIFY_LDT_CONTENTS_*`): data, expand-down stack,
/// code. `3` is the reserved fourth encoding — a conforming code segment,
/// which is only accepted as a not-present entry and only through the new
/// sub-function.
pub const CONTENTS_DATA: u32 = 0;
pub const CONTENTS_STACK: u32 = 1;
pub const CONTENTS_CODE: u32 = 2;
pub const CONTENTS_RESERVED: u32 = 3;

/// Whether this kernel accepts 16-bit (non-`seg_32bit`) LDT segments.
///
/// TRUE, matching the reference's `X86_16BIT` default and the configuration
/// the distribution kernel this port targets ships. The reference's only
/// other reason to refuse is a paravirtualised guest without ESPFIX64, which
/// this kernel is not: it runs on bare metal or hardware virtualisation with
/// its own IRET path. Kept as a named constant rather than inlined `true` so
/// the refusal arm below stays live code with a live test.
pub const ALLOW_16BIT_SEGMENTS: bool = true;

/// The `func` argument's four defined sub-functions.
///
/// Every other value — including negative ones — is ENOSYS, not EINVAL: the
/// reference seeds its return with ENOSYS and only a matching `switch` arm
/// overwrites it. A caller probing for an unimplemented sub-function must be
/// able to tell "no such operation" from "bad arguments".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdtFunc {
    /// `0` — copy this process's LDT out to userspace.
    Read,
    /// `1` — install one entry, ORIGINAL semantics (`oldmode`): a zero
    /// base+limit clears the entry, `contents == 3` is refused outright, and
    /// the `avl` bit is forced to zero.
    Write,
    /// `2` — copy out the "default LDT", which is a fixed run of zeroes.
    ReadDefault,
    /// `0x11` — install one entry, CURRENT semantics: only a fully empty
    /// `user_desc` clears, `contents == 3` is allowed when not present, and
    /// `avl` is taken from `useable`.
    WriteNew,
}

impl LdtFunc {
    /// True for the sub-function that carries the original (`oldmode`)
    /// write rules. Sub-function `1` is the old one and `0x11` the new one —
    /// the numerically larger code is the newer contract.
    /// # C: O(1)
    pub fn oldmode(self) -> bool { matches!(self, LdtFunc::Write) }
}

/// Resolve `func` to a sub-function, or `None` for ENOSYS.
/// # C: O(1)
pub fn classify(func: i32) -> Option<LdtFunc> {
    match func {
        0 => Some(LdtFunc::Read),
        1 => Some(LdtFunc::Write),
        2 => Some(LdtFunc::ReadDefault),
        0x11 => Some(LdtFunc::WriteNew),
        _ => None,
    }
}

/// The errno an unrecognised `func` produces.
/// # C: O(1)
pub fn unsupported_func_errno() -> i64 { -(Errno::Enosys.as_i32() as i64) }

/// Decoded `struct user_desc`.
///
/// The bitfield word is one `unsigned int` whose bits the compiler assigns
/// from the least significant end on both supported targets, so the wire
/// order is `seg_32bit, contents(2), read_exec_only, limit_in_pages,
/// seg_not_present, useable, lm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UserDesc {
    pub entry_number: u32,
    pub base_addr: u32,
    pub limit: u32,
    pub seg_32bit: bool,
    pub contents: u32,
    pub read_exec_only: bool,
    pub limit_in_pages: bool,
    pub seg_not_present: bool,
    pub useable: bool,
    /// Present only in the 64-bit `user_desc`. Never allowed to reach the
    /// descriptor's `L` bit — see `desc::fill_ldt`.
    pub lm: bool,
}

/// Bit positions inside the `user_desc` flag word.
const F_SEG_32BIT: u32 = 1 << 0;
const F_CONTENTS_SHIFT: u32 = 1;
const F_CONTENTS_MASK: u32 = 0b11;
const F_READ_EXEC_ONLY: u32 = 1 << 3;
const F_LIMIT_IN_PAGES: u32 = 1 << 4;
const F_SEG_NOT_PRESENT: u32 = 1 << 5;
const F_USEABLE: u32 = 1 << 6;
const F_LM: u32 = 1 << 7;

impl UserDesc {
    /// Decode the 16 wire bytes userspace supplied.
    /// # C: O(1)
    pub fn decode(raw: &[u8; USER_DESC_BYTES as usize]) -> Self {
        let word = |o: usize| u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]);
        let flags = word(12);
        Self {
            entry_number: word(0),
            base_addr: word(4),
            limit: word(8),
            seg_32bit: flags & F_SEG_32BIT != 0,
            contents: (flags >> F_CONTENTS_SHIFT) & F_CONTENTS_MASK,
            read_exec_only: flags & F_READ_EXEC_ONLY != 0,
            limit_in_pages: flags & F_LIMIT_IN_PAGES != 0,
            seg_not_present: flags & F_SEG_NOT_PRESENT != 0,
            useable: flags & F_USEABLE != 0,
            lm: flags & F_LM != 0,
        }
    }

    /// Re-encode to the wire form. Used only by tests and by any future
    /// `get_thread_area`-style read-back; kept beside `decode` so the two can
    /// never disagree about bit positions.
    /// # C: O(1)
    pub fn encode(&self) -> [u8; USER_DESC_BYTES as usize] {
        let mut raw = [0u8; USER_DESC_BYTES as usize];
        raw[0..4].copy_from_slice(&self.entry_number.to_le_bytes());
        raw[4..8].copy_from_slice(&self.base_addr.to_le_bytes());
        raw[8..12].copy_from_slice(&self.limit.to_le_bytes());
        let mut flags = (self.contents & F_CONTENTS_MASK) << F_CONTENTS_SHIFT;
        if self.seg_32bit { flags |= F_SEG_32BIT; }
        if self.read_exec_only { flags |= F_READ_EXEC_ONLY; }
        if self.limit_in_pages { flags |= F_LIMIT_IN_PAGES; }
        if self.seg_not_present { flags |= F_SEG_NOT_PRESENT; }
        if self.useable { flags |= F_USEABLE; }
        if self.lm { flags |= F_LM; }
        raw[12..16].copy_from_slice(&flags.to_le_bytes());
        raw
    }
}

#[cfg(test)]
mod tests;
