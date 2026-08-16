//! The FAT32 information sector, and the free-cluster accounting it seeds.
//!
//! A FAT32 volume caches two numbers in a sector of its own: how many clusters
//! are free, and which cluster was handed out last. Neither is authoritative —
//! any system that wrote the volume may have left them stale, and the reference
//! treats the free count as a hint that must be re-derived unless the mount
//! explicitly asks for it to be trusted. Getting that trust rule wrong is the
//! difference between `statfs` reporting a plausible lie and reporting the
//! truth.
//!
//! Module manifest:
//! - `layout`: the sector's signatures, offsets and the unknown sentinel.
//! - `state`:  the mounted volume's free count and allocation hint, and the
//!   rules for when each is trusted, recomputed and written back.

pub mod layout;
pub mod state;

pub use layout::{
    parse, sector_number, write_back, FsInfo, FSINFO_FREE_UNKNOWN, FSINFO_SIG1, FSINFO_SIG2,
    FSINFO_TRAIL_SIG,
};
pub use state::FreeState;

#[cfg(test)]
#[path = "fsinfo/tests.rs"]
mod tests;
