// kexec: stage a replacement kernel image now, boot it from `reboot(2)` later.
//
// Owns everything behind `kexec_load(2)` (slot 246) and `kexec_file_load(2)`
// (slot 320); the syscall shims in `crates/kernel/syscalls` parse and encode
// only (`docs/53`). `reboot(LINUX_REBOOT_CMD_KEXEC)` enters through
// `store::kernel_kexec`.
//
// Module manifest:
// - `uapi`:     flag bits, arch tags, segment record, relocation-entry encoding.
// - `validate`: every refusal decision, in the reference's order — host-tested.
// - `frames`:   the page supply (trait + the buddy-backed running-kernel impl).
// - `image`:    the staged image: relocation list, control pages, segment copy.
// - `stage`:    `kimage_alloc_init` + the per-segment load, global-state free.
// - `file_load`: `kexec_file_load`'s ladder and the arch loader registry.
// - `store`:    the two image slots, the kexec lock, `kernel_kexec`.
// - `machine`:  the arch relocate-and-enter step — refused, with a diagnosis.
// - `tests`:    host-run provenance for the order and the staging invariants.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod uapi;
pub mod validate;
pub mod frames;
pub mod image;
pub mod stage;
pub mod file_load;
pub mod store;
pub mod machine;

#[cfg(test)]
mod tests;

pub use uapi::{ImageType, KexecSegment, KEXEC_FILE_FLAGS, KEXEC_FILE_ON_CRASH,
    KEXEC_FILE_NO_INITRAMFS, KEXEC_FILE_SIZE_MAX, KEXEC_FILE_UNLOAD, KEXEC_FLAGS,
    KEXEC_ON_CRASH, KEXEC_SEGMENT_MAX, KEXEC_SEGMENT_SIZE};
pub use validate::{arch_ok, cmdline_ok, crash_entry_ok, image_type, kexec_file_load_check,
    kexec_load_check, sanity_check_segment_list, signature_check_required, CrashRange, Error,
    KResult};
pub use frames::{Frames, PmmFrames};
pub use image::{KImage, SegmentSource};
pub use stage::{stage_image, KernelSource, Limits, UserSource};
pub use store::{disable_load, do_kexec_load, drop_image, install_staged, kernel_kexec,
    kexec_crash_loaded, kexec_loaded, load_disabled, load_permitted, with_kexec_lock};
pub use file_load::{kexec_file_load, FileImage, FileLoader};
