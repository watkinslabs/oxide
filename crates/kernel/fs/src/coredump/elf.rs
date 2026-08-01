// The dump image itself: an `ET_CORE` ELF object.
//
// Module manifest:
//   uapi    ELF and note constants the format fixes
//   layout  per-arch register-block sizes and `elf_prstatus`/`elf_prpsinfo` offsets
//   input   the injected description of the dying process the builder consumes
//   notes   note-segment construction (prstatus, prpsinfo, auxv, files, fp)
//   build   two-pass file layout and emission
//   tests   hosted coverage of every byte offset the format fixes

pub mod uapi;
pub mod layout;
pub mod input;
pub mod notes;
pub mod build;

pub use layout::CoreArch;
pub use input::{
    CoreIdentity, CoreImageError, CoreImageInput, CoreMem, CoreSegFile, CoreSegment,
    CoreState, CoreThread, CoreTimes, CoreTimeval,
    SEG_EXEC, SEG_READ, SEG_WRITE,
};
pub use build::{build_core_image, CORE_PAGE_SIZE};

#[cfg(test)]
mod tests;
