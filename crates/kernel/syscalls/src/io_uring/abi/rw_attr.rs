// The attribute vector a read or write entry may carry.
//
// A transfer entry can point at a typed attribute record beside its payload:
// `attr_type_mask` names the attribute types present and `attr_ptr` points at
// the record. One type is defined — protection information, the integrity
// bytes a storage target checks the payload against — and an entry naming any
// other is malformed. That the fields are READ at all is the whole of the
// `IORING_FEAT_RW_ATTR` contract: without it a caller cannot tell a kernel
// that honours the attribute from one that silently transfers without it.
//
// Ungated on purpose: the record's wire form, the mask ladder and the target
// admission are the decisions, and the dispatch file that calls them is
// kernel-gated (CLAUDE.md phantom-test rule).

use syscall::errno::Errno;

use super::ops::{IORING_OP_READ, IORING_OP_READV, IORING_OP_READ_FIXED, IORING_OP_WRITE,
                 IORING_OP_WRITEV, IORING_OP_WRITE_FIXED};

/// `IORING_RW_ATTR_FLAG_PI` — the record is protection information.
pub const IORING_RW_ATTR_FLAG_PI: u64 = 1 << 0;

/// `sizeof(struct io_uring_attr_pi)`.
pub const ATTR_PI_BYTES: usize = 32;

/// The protection-information record, decoded.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct AttrPi {
    /// Integrity-check controls the target applies to the transfer.
    pub flags: u16,
    /// The application tag carried with each protection interval.
    pub app_tag: u16,
    /// Length of the integrity buffer.
    pub len: u32,
    /// The integrity buffer, beside the payload.
    pub addr: u64,
    /// The reference tag the first interval is seeded with.
    pub seed: u64,
}

/// Whether the opcode reads the attribute words at all. Every other opcode
/// gives those two words a meaning of its own, so a mask read there would be
/// reading somebody else's field. # C: O(1)
pub fn op_takes_attr(op: u8) -> bool {
    matches!(op, IORING_OP_READ | IORING_OP_WRITE | IORING_OP_READV | IORING_OP_WRITEV
                 | IORING_OP_READ_FIXED | IORING_OP_WRITE_FIXED)
}

/// Whether the entry carries an attribute record, refusing a mask that names
/// anything but the one defined type. A mask is not a bit set to be filtered:
/// an unknown type means the caller expects a guarantee this kernel would not
/// give, so it is `EINVAL` rather than a silently dropped bit.
/// # C: O(1)
pub fn wants_attr(mask: u64) -> Result<bool, Errno> {
    if mask == 0 { return Ok(false); }
    if mask != IORING_RW_ATTR_FLAG_PI { return Err(Errno::Einval); }
    Ok(true)
}

/// Decode the protection-information record. The reserved word must be zero:
/// it is where a later type grows, and a caller that set it is asking for
/// something this kernel would ignore. # C: O(1)
pub fn parse_pi(b: &[u8; ATTR_PI_BYTES]) -> Result<AttrPi, Errno> {
    let g16 = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
    let g32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let g64 = |o: usize| {
        let mut v = [0u8; 8]; v.copy_from_slice(&b[o..o + 8]); u64::from_le_bytes(v)
    };
    if g64(24) != 0 { return Err(Errno::Einval); }
    Ok(AttrPi { flags: g16(0), app_tag: g16(2), len: g32(4), addr: g64(8), seed: g64(16) })
}

/// Whether the description can carry the attribute.
///
/// Two separate answers, and the order matters: a target with no integrity
/// metadata at all cannot serve the request in any configuration, which is a
/// malformed entry; a target that HAS it but is being read or written through
/// the page cache could serve it, just not on this description, which is why
/// that one is `EOPNOTSUPP` and not `EINVAL`.
/// # C: O(1)
pub fn admit_target(has_metadata: bool, direct: bool) -> Result<(), Errno> {
    if !has_metadata { return Err(Errno::Einval); }
    if !direct { return Err(Errno::Eopnotsupp); }
    Ok(())
}

#[cfg(test)]
#[path = "rw_attr/tests.rs"]
mod tests;
