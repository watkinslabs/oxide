//! BPF LSM.
//!
//! Module manifest:
//!
//!   hooks.rs     the hook stubs this kernel publishes as attach targets
//!   registry.rs  attached programs and the chained invocation
//!
//! A hook target is named by a type id in the kernel's own type
//! information, resolved by `bpf::btf` — this module owns no second
//! attach-target mechanism.

extern crate alloc;

use vfs::InodeRef;

#[path = "bpf_lsm/hooks.rs"]
mod hooks;
#[path = "bpf_lsm/registry.rs"]
mod registry;

pub use hooks::{HOOKS, Hook, Ret, SLOT_BYTES, Spec, context_bytes, hook_by_stub_name, spec};
pub use registry::{register, run, unregister};

/// Callable BPF LSM `file_open` hook. Runs the attached chain and hands
/// the first non-zero answer back as the open's verdict.
/// # C: O(attached programs × instructions run)
/// # Ctx: process
/// # Sleeps: no
pub fn file_open(inode: &InodeRef) -> Result<(), i64> {
    let arg = alloc::sync::Arc::as_ptr(inode) as *const u8 as usize as u64;
    match run(Hook::FileOpen, &[arg]) {
        0 => Ok(()),
        refusal => Err(refusal),
    }
}
