// What one multicast source-filter write is admitted against, before its
// source list is read.
//
// A filter write is the only socket option whose size the caller chooses, so it
// is the only one with a memory ceiling of its own: the whole option is bounded
// by the per-namespace option-memory limit, and the source count by the
// family's own maximum. Both refusals are ENOBUFS and both precede the
// length-versus-count screen, which is EINVAL — a caller that asks for a
// million sources is told it asked for too many, not that its buffer is the
// wrong size.

use syscall::errno::Errno;

/// `net.ipv4.igmp_max_msf`.
pub const DEFAULT_IGMP_MAX_MSF: i64 = 10;
/// `sysctl_mld_max_msf`, a global rather than a per-namespace leaf.
pub const DEFAULT_MLD_MAX_MSF: i64 = 64;

/// Source counts whose byte size overflows 32 bits before any ceiling is
/// consulted: one entry per source at four bytes, and at 128.
pub const MAX_NUMSRC_NARROW: u32 = 0x3fff_fffc;
pub const MAX_NUMSRC_WIDE: u32 = 0x01ff_ffff;

/// The ceilings one write is judged against. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Limits {
    /// `net.core.optmem_max` — the whole option's byte ceiling.
    pub optmem_max: usize,
    /// `igmp_max_msf` / `mld_max_msf` — the source-count ceiling.
    pub max_msf: i64,
    /// The count at which the source list's size overflows 32 bits.
    pub numsrc_overflow: u32,
}

/// The fixed part of the request, and the bytes one source costs. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Shape { pub header: u32, pub entry: u32 }

/// `ip_msfilter` / `group_filter`: the two request shapes.
pub const IP_MSFILTER: Shape = Shape { header: 16, entry: 4 };
pub const GROUP_FILTER: Shape = Shape { header: 144, entry: 128 };

/// Whether the caller's buffer is even large enough to name a count. # C: O(1)
pub fn admit_length(optlen: u32, shape: Shape, limits: Limits) -> Result<(), Errno> {
    if optlen < shape.header { return Err(Errno::Einval); }
    if optlen as usize > limits.optmem_max { return Err(Errno::Enobufs); }
    Ok(())
}

/// Whether the source count the caller named is one this socket may hold, and
/// whether the buffer actually carries that many. # C: O(1)
pub fn admit_sources(optlen: u32, numsrc: u32, shape: Shape, limits: Limits)
    -> Result<(), Errno>
{
    if numsrc >= limits.numsrc_overflow || i64::from(numsrc) > limits.max_msf {
        return Err(Errno::Enobufs);
    }
    let need = u64::from(shape.header)
        .saturating_add(u64::from(numsrc).saturating_mul(u64::from(shape.entry)));
    if need > u64::from(optlen) { return Err(Errno::Einval); }
    Ok(())
}

#[cfg(test)]
#[path = "msfilter/tests.rs"]
mod tests;
