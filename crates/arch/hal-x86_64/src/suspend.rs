// x86_64 deep-sleep CPU state per `32a§9` and `54§1`.
//
// Module manifest:
// - `state`:      the one processor-context record, its asm offsets, and the
//                 pure rules about where a resume vector may be placed.
// - `cpu_state`:  reading the live registers into the record and writing them
//                 back, in the order a resume can survive.
// - `lowlevel`:   the asm that captures the resume point, hands the machine to
//                 the platform enter, and lands the resume.
// - `trampoline`: the real-mode → long-mode stub firmware resumes into.

pub mod state;
pub mod cpu_state;
pub mod lowlevel;
pub mod trampoline;

pub use state::{DescPtr, SavedCpuState, REAL_MODE_LIMIT, RESUME_PAGE_BYTES, SUSPEND_MAGIC,
    resume_vector_placeable, resume_vector_segment};
pub use cpu_state::{restore_processor_state, save_processor_state};
pub use lowlevel::{suspend_lowlevel, wakeup_entry};
pub use trampoline::{install_wakeup_trampoline, set_wakeup_page_reserved, wakeup_page_reserved,
    WAKEUP_TRAMP_PA};
