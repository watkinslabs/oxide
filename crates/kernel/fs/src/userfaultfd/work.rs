// The page work every UFFDIO_* resolve performs, behind one arch-neutral
// surface.
//
// Every DECISION these paths could make (range validation, destination
// acceptance, mode words, return protocol) lives in the ungated `policy`
// modules; what is behind this manifest is the mechanical page work, so the
// target gate costs no test coverage.
//
// Module manifest:
//   - leaf: UNGATED — every judgement these paths make about a page-table
//     leaf, generic over the walker, so the encodings can be exercised hosted.
//   - install: the fill loop shared by COPY, ZEROPAGE and CONTINUE.
//   - wp: the write-protect arm/disarm range walk.
//   - poison: the poison-marker install.
//   - movepg: page relocation between two anonymous mappings.
//   - hosted: the same surface for the hosted test build, where there is no
//     page table to touch.

use syscall::errno::Errno;

use super::policy::FillKind;

/// One fill request: what to write into `[dst, dst+len)` and whether the
/// installed pages start out write-protected.
pub struct FillReq {
    pub kind: FillKind,
    pub dst: u64,
    /// The monitor's source bytes, for a copy.
    pub src: Option<u64>,
    pub len: u64,
    /// Install the pages carrying the write-protect marker.
    pub wp: bool,
}

/// Bytes completed plus the first error, for every op that reports progress.
pub type Progress = (u64, Option<Errno>);

pub mod leaf;

#[cfg(target_os = "oxide-kernel")]
mod arch;
#[cfg(target_os = "oxide-kernel")]
mod install;
#[cfg(target_os = "oxide-kernel")]
mod wp;
#[cfg(target_os = "oxide-kernel")]
mod poison;
#[cfg(target_os = "oxide-kernel")]
mod movepg;
#[cfg(not(target_os = "oxide-kernel"))]
mod hosted;

#[cfg(target_os = "oxide-kernel")]
pub use install::fill_pages;
#[cfg(target_os = "oxide-kernel")]
pub use wp::wp_range;
#[cfg(target_os = "oxide-kernel")]
pub use poison::poison_range;
#[cfg(target_os = "oxide-kernel")]
pub use movepg::move_pages;
#[cfg(not(target_os = "oxide-kernel"))]
pub use hosted::{fill_pages, move_pages, poison_range, wp_range};
