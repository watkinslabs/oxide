//! The information sector's on-disk shape.
//!
//! Three signatures guard it, and only two of them decide validity. The
//! reference accepts the sector on the leading and mid signatures alone and
//! never looks at the trailing one, so a volume whose formatter omitted the
//! trailer still has its hint honoured. Rejecting on the trailer would discard
//! usable state on real media, so the trailer is read and reported, not
//! enforced.

use crate::geometry::FAT_START_ENT;

/// Leading signature, at the first byte of the sector.
pub const FSINFO_SIG1: u32 = 0x4161_5252;
/// Mid signature, immediately before the two counters.
pub const FSINFO_SIG2: u32 = 0x6141_7272;
/// Trailing boot signature. Read and reported; validity does not depend on it.
pub const FSINFO_TRAIL_SIG: u32 = 0xAA55_0000;

/// The value both counters carry when their writer did not know them.
pub const FSINFO_FREE_UNKNOWN: u32 = 0xFFFF_FFFF;

/// Sector the information block occupies when the boot sector names none. A
/// zero in that field means "not stated", not "sector zero" — sector zero is
/// the boot sector itself.
pub const FSINFO_DEFAULT_SECTOR: u32 = 1;

/// Byte offsets within the sector.
pub mod off {
    pub const SIG1: usize = 0;
    pub const SIG2: usize = 484;
    pub const FREE_CLUSTERS: usize = 488;
    pub const NEXT_CLUSTER: usize = 492;
    pub const TRAIL_SIG: usize = 508;
}

/// Bytes the sector must hold before any field can be read.
pub const FSINFO_MIN_BYTES: usize = off::TRAIL_SIG + 4;

/// The two counters and the trailer, once read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FsInfo {
    /// Free clusters the last writer believed the volume had.
    /// `None` when it carried the unknown sentinel.
    pub free_clusters: Option<u32>,
    /// The cluster most recently handed out, used as the next search's hint.
    /// `None` when it carried the unknown sentinel.
    pub next_cluster: Option<u32>,
    /// Whether the trailing signature was the expected one. Informational: the
    /// reference does not gate acceptance on it.
    pub trailer_ok: bool,
}

/// Which sector holds the information block, given the boot sector's field.
/// # C: O(1)
pub fn sector_number(declared: u32) -> u32 {
    if declared == 0 { FSINFO_DEFAULT_SECTOR } else { declared }
}

fn le32(sector: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([sector[at], sector[at + 1], sector[at + 2], sector[at + 3]])
}

fn counter(raw: u32) -> Option<u32> {
    if raw == FSINFO_FREE_UNKNOWN { None } else { Some(raw) }
}

/// Read the information sector.
///
/// `None` when either guarding signature is wrong — the sector then carries
/// nothing, and the volume's free count has to be derived by scanning. A short
/// buffer is the same answer for the same reason.
/// # C: O(1)
pub fn parse(sector: &[u8]) -> Option<FsInfo> {
    if sector.len() < FSINFO_MIN_BYTES { return None; }
    if le32(sector, off::SIG1) != FSINFO_SIG1 { return None; }
    if le32(sector, off::SIG2) != FSINFO_SIG2 { return None; }
    Some(FsInfo {
        free_clusters: counter(le32(sector, off::FREE_CLUSTERS)),
        next_cluster: counter(le32(sector, off::NEXT_CLUSTER)),
        trailer_ok: le32(sector, off::TRAIL_SIG) == FSINFO_TRAIL_SIG,
    })
}

/// Write the two counters back into an existing information sector.
///
/// Refuses a sector whose signatures do not match, exactly as the reference
/// does: an unrecognised sector is left alone rather than overwritten, because
/// whatever it holds belongs to something else. A counter that is not known
/// here is left as it was found rather than replaced with the sentinel — the
/// stale value is no worse than the sentinel and the reference keeps it.
/// # C: O(1)
pub fn write_back(sector: &mut [u8], free_clusters: Option<u32>, next_cluster: Option<u32>) -> bool {
    if parse(sector).is_none() { return false; }
    if let Some(free) = free_clusters {
        sector[off::FREE_CLUSTERS..off::FREE_CLUSTERS + 4].copy_from_slice(&free.to_le_bytes());
    }
    if let Some(next) = next_cluster {
        sector[off::NEXT_CLUSTER..off::NEXT_CLUSTER + 4].copy_from_slice(&next.to_le_bytes());
    }
    true
}

/// Build an information sector from scratch, for a volume being formatted or a
/// sector being replaced wholesale. # C: O(sector bytes)
pub fn encode(sector: &mut [u8], free_clusters: Option<u32>, next_cluster: Option<u32>) -> bool {
    if sector.len() < FSINFO_MIN_BYTES { return false; }
    for byte in sector.iter_mut() { *byte = 0; }
    sector[off::SIG1..off::SIG1 + 4].copy_from_slice(&FSINFO_SIG1.to_le_bytes());
    sector[off::SIG2..off::SIG2 + 4].copy_from_slice(&FSINFO_SIG2.to_le_bytes());
    sector[off::TRAIL_SIG..off::TRAIL_SIG + 4].copy_from_slice(&FSINFO_TRAIL_SIG.to_le_bytes());
    let free = free_clusters.unwrap_or(FSINFO_FREE_UNKNOWN);
    let next = next_cluster.unwrap_or(FSINFO_FREE_UNKNOWN);
    sector[off::FREE_CLUSTERS..off::FREE_CLUSTERS + 4].copy_from_slice(&free.to_le_bytes());
    sector[off::NEXT_CLUSTER..off::NEXT_CLUSTER + 4].copy_from_slice(&next.to_le_bytes());
    true
}

/// The hint a freshly mounted volume starts from when the sector said nothing.
/// # C: O(1)
pub fn default_hint() -> u32 { FAT_START_ENT }
