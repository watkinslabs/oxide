//! What this filesystem publishes into `/proc/fs`, in terms that tree does not
//! have to know about.
//!
//! An entry is a name, a permission, something that renders bytes when it is
//! read, and — for the one entry that is a control rather than a report —
//! something that consumes a write. The tree hosting it owns the directory,
//! the inode and the read plumbing; the filesystem owns the value. Describing
//! an entry as data keeps that split honest: this crate never names a `/proc`
//! type, and `/proc` never names one of this crate's.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::KResult;

/// Renders an entry's current bytes.
pub type ShowFn = Arc<dyn Fn() -> KResult<Vec<u8>> + Send + Sync>;

/// Consumes a write to an entry, returning the count accepted.
pub type StoreFn = Arc<dyn Fn(&[u8]) -> KResult<usize> + Send + Sync>;

/// Permission of a report.
pub const RO: u16 = 0o444;

/// Permission of a control: readable, and writable by the owner.
pub const RW: u16 = 0o644;

/// One entry to publish, relative to the filesystem's own directory.
pub struct Attr {
    /// Directory under the filesystem's own, empty for a direct child.
    pub dir:   String,
    pub name:  &'static str,
    pub mode:  u16,
    pub show:  ShowFn,
    /// `None` for a report; a report refuses writes rather than accepting and
    /// discarding them.
    pub store: Option<StoreFn>,
}

impl Attr {
    /// A read-only entry. # C: O(1)
    pub fn ro(dir: &str, name: &'static str, show: ShowFn) -> Attr {
        Attr { dir: dir.to_string(), name, mode: RO, show, store: None }
    }

    /// A writable entry. # C: O(1)
    pub fn rw(dir: &str, name: &'static str, show: ShowFn, store: StoreFn) -> Attr {
        Attr { dir: dir.to_string(), name, mode: RW, show, store: Some(store) }
    }
}

/// A string and a newline. # C: O(len)
pub fn line_str(s: &str) -> Vec<u8> { format!("{s}\n").into_bytes() }

/// The directory name one mount's entries live under.
///
/// A mount's directory is named for the device it came from, and a directory
/// name cannot hold a separator, so the source's last component is the name.
/// A source with no usable last component falls back to the filesystem's own
/// name, which is what a mount from something that is not a path would
/// otherwise have no name at all.
/// # C: O(len)
pub fn dev_id(source: &str) -> String {
    match source.rsplit('/').find(|c| !c.is_empty() && *c != "." && *c != "..") {
        Some(c) => c.to_string(),
        None => crate::mount::NTFS_NAME.to_string(),
    }
}

/// Withdraws one mount's published entries, given its directory name.
pub type Teardown = fn(&str);

/// The withdrawal the tree installed.
///
/// A mount publishes into `/proc/fs` from the code that mounts it, which holds
/// both this crate and that tree. Unmount has no such place: it arrives at
/// this filesystem's own superblock operations, which cannot name a
/// pseudo-filesystem. So the integrator leaves the withdrawal here on the way
/// in, and unmount runs it on the way out.
static TEARDOWN: sync::Spinlock<Option<Teardown>, sync::TaskList> = sync::Spinlock::new(None);

/// Install the withdrawal. Called once, where the surfaces are published.
/// # C: O(1)
pub fn set_teardown(f: Teardown) { *TEARDOWN.lock() = Some(f); }

/// Withdraw one mount's entries. Does nothing when nothing was published.
/// # C: cost of the withdrawal
pub fn run_teardown(dev: &str) {
    let f = *TEARDOWN.lock();
    if let Some(f) = f { f(dev); }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mount directory's name must be a single component: a source path
    /// used whole would create a directory chain, and the withdraw at unmount
    /// would not match what the mount published.
    #[test]
    fn the_mount_directory_is_the_sources_last_component() {
        assert_eq!(dev_id("/dev/sda1"), "sda1");
        assert_eq!(dev_id("/dev/mapper/win"), "win");
        assert_eq!(dev_id("vdb"), "vdb");
        assert_eq!(dev_id("/dev/vdc/"), "vdc");
    }

    /// Unmount must be able to withdraw what mount published, or a directory
    /// reporting on an unreachable volume outlives it.
    #[test]
    fn the_teardown_hook_runs_for_the_mount_it_is_given() {
        use core::sync::atomic::{AtomicU32, Ordering};
        static SEEN: AtomicU32 = AtomicU32::new(0);
        fn note(dev: &str) { if dev == "sdz9" { SEEN.fetch_add(1, Ordering::Relaxed); } }
        set_teardown(note);
        run_teardown("sdz9");
        run_teardown("other");
        assert_eq!(SEEN.load(Ordering::Relaxed), 1);
    }

    /// A source that names no component at all still gets a directory rather
    /// than an empty name the tree would refuse.
    #[test]
    fn a_source_with_no_component_falls_back_to_the_filesystem_name() {
        assert_eq!(dev_id("/"), "ntfs3");
        assert_eq!(dev_id(""), "ntfs3");
    }
}
