//! Every mounted volume, in mount order, so one file can report them all.
//!
//! The status report is a SINGLE file describing every mount rather than one
//! file per mount, because the question it answers — which of these volumes
//! is short of space, which is being cleaned hardest — is a comparison. That
//! forces a list somewhere, and it lives here rather than beside the mounts
//! so that the report's reader and the mount path share one order: the
//! banner numbers each section by its position in this list.
//!
//! Rendering happens OUTSIDE this lock. A section is rendered by taking the
//! volume's own lock, and holding the list across that would order the two
//! locks list-then-volume while a mount that publishes itself holds them the
//! other way round. The list is copied, released, and then walked.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::KResult;

/// Renders one volume's section, given its position in the list.
pub type PartFn = Arc<dyn Fn(usize) -> KResult<String> + Send + Sync>;

/// The mounts, in the order they were published.
static MOUNTS: sync::Spinlock<Vec<(String, PartFn)>, sync::TaskList> =
    sync::Spinlock::new(Vec::new());

/// The directory the report lives in, under the debug tree. # C: O(1)
pub const STATUS_DIR: &str = crate::mount::F2FS_NAME;

/// The report's file name. # C: O(1)
pub const STATUS_NAME: &str = "status";

/// Where the report is published. # C: O(1)
pub const STATUS_PATH: &str = "/sys/kernel/debug/f2fs/status";

/// Add one mount's section to the report.
///
/// A device that is already listed is REPLACED rather than appended: a mount
/// of the same device after an unmount that failed to withdraw would
/// otherwise report the dead volume forever, and the live one beside it.
/// # C: O(N mounts)
pub fn register(dev: &str, f: PartFn) {
    let mut g = MOUNTS.lock();
    match g.iter().position(|(d, _)| d == dev) {
        Some(i) => g[i] = (dev.to_string(), f),
        None => g.push((dev.to_string(), f)),
    }
}

/// Withdraw one mount's section. # C: O(N mounts)
pub fn unregister(dev: &str) {
    let mut g = MOUNTS.lock();
    if let Some(i) = g.iter().position(|(d, _)| d == dev) { g.remove(i); }
}

/// How many mounts the report covers. # C: O(1)
pub fn mounted() -> usize { MOUNTS.lock().len() }

/// Whether a device is listed. # C: O(N mounts)
pub fn is_registered(dev: &str) -> bool { MOUNTS.lock().iter().any(|(d, _)| d == dev) }

/// The whole report.
///
/// A section that cannot be rendered — a volume whose medium has gone, most
/// likely — is SKIPPED rather than failing the read. One unreachable volume
/// must not hide the others, which are the ones the reader can still act on.
/// # C: O(N mounts * one section each)
pub fn status_body() -> KResult<Vec<u8>> {
    let list: Vec<(String, PartFn)> = MOUNTS.lock().clone();
    let mut out = String::new();
    for (i, (_, f)) in list.iter().enumerate() {
        if let Ok(part) = f(i) { out.push_str(&part); }
    }
    Ok(out.into_bytes())
}

/// The report as something a pseudo-filesystem can publish. # C: O(1)
pub fn status_show() -> crate::fsattr::ShowFn { Arc::new(status_body) }

/// Empty the list. For a test that needs the report to describe only what it
/// registered; nothing in a running system withdraws every mount at once.
/// # C: O(N mounts)
#[cfg(test)]
pub fn clear() { MOUNTS.lock().clear(); }
