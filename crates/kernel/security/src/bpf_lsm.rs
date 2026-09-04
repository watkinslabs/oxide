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

pub use hooks::{Arg, ArgType, HOOKS, Hook, Ret, SLOT_BYTES, Spec, context_bytes,
                hook_by_stub_name, spec, task_struct};
pub use registry::{register, run, unregister};

/// Common LSM dispatcher provider for BPF's `file_open` hook.
pub(crate) fn open_hook(ctx: &crate::lsm::OpenContext<'_>) -> Result<u64, i64> {
    file_open(ctx.inode).map(|()| ctx.access)
}

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

fn task_view(target: &sched::Task) -> [u8; task_struct::SIZE] {
    use core::sync::atomic::Ordering;
    let mut bytes = [0u8; task_struct::SIZE];
    let pid = target.tid as i32;
    let raw_tgid = target.tgid.load(Ordering::Acquire);
    let tgid = if raw_tgid == 0 { target.tid } else { raw_tgid } as i32;
    bytes[task_struct::PID..task_struct::PID + task_struct::WORD]
        .copy_from_slice(&pid.to_ne_bytes());
    bytes[task_struct::TGID..task_struct::TGID + task_struct::WORD]
        .copy_from_slice(&tgid.to_ne_bytes());
    bytes
}

fn task_bpf_answer(hook: Hook, target: &sched::Task, tail: &[u64]) -> Result<(), i64> {
    let view = task_view(target);
    let base = view.as_ptr() as usize as u64;
    debug_assert!(tail.len() <= 1);
    let mut args = [base, 0];
    if let Some(value) = tail.first() { args[1] = *value; }
    match registry::run_task(hook, &args[..1 + tail.len()], base, &view) {
        0 => Ok(()),
        refusal => Err(refusal),
    }
}

/// Common LSM dispatcher provider for BPF's `task_setnice` hook.
/// # C: O(attached programs × instructions run)
pub(crate) fn task_setnice_hook(_caller: &sched::Task, target: &sched::Task, nice: i32)
    -> Result<(), i64>
{
    task_bpf_answer(Hook::TaskSetNice, target, &[nice as i64 as u64])
}

/// Common LSM dispatcher provider for BPF's `task_setscheduler` hook.
/// # C: O(attached programs × instructions run)
pub(crate) fn task_setscheduler_hook(_caller: &sched::Task, target: &sched::Task)
    -> Result<(), i64>
{
    task_bpf_answer(Hook::TaskSetScheduler, target, &[])
}
