//! What this filesystem publishes into `/proc/fs`, `/sys/fs` and debugfs, in
//! terms neither of those trees has to know about.
//!
//! A pseudo-filesystem entry is a name, a permission and something that
//! renders bytes when it is read. The trees that host those entries own the
//! directory, the inode and the read plumbing; the filesystem owns the value.
//! Describing an entry as data keeps that split honest — this crate never
//! names a `/sys` type, and `/sys` never names one of this crate's.
//!
//! Every renderer here reads the LIVE volume. An attribute that answered from
//! bytes captured at mount would report the state at mount forever, and there
//! is nothing in a reader that could tell the difference.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::KResult;

/// Renders an entry's current bytes.
pub type ShowFn = Arc<dyn Fn() -> KResult<Vec<u8>> + Send + Sync>;

/// Consumes a write to an entry, returning the count accepted.
pub type StoreFn = Arc<dyn Fn(&[u8]) -> KResult<usize> + Send + Sync>;

/// Permission of a report — everything a reader may look at and nothing more.
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

/// One decimal number and a newline — the shape a sysfs scalar takes.
/// # C: O(1)
pub fn line_u64(v: u64) -> Vec<u8> { format!("{v}\n").into_bytes() }

/// One hexadecimal number and a newline, no `0x` — the shape a sysfs flag
/// word takes. # C: O(1)
pub fn line_hex(v: u64) -> Vec<u8> { format!("{v:x}\n").into_bytes() }

/// A string and a newline. # C: O(len)
pub fn line_str(s: &str) -> Vec<u8> { format!("{s}\n").into_bytes() }

/// The directory name one mount's entries live under.
///
/// A filesystem's per-mount directory is named for the device the mount came
/// from, and a directory name cannot hold a separator — so the source's last
/// component is the name, exactly as a block device's own short name is
/// upstream. A source with no usable last component falls back to the
/// filesystem's name, which is what a mount from something that is not a path
/// would otherwise have no name at all.
/// # C: O(len)
pub fn dev_id(source: &str) -> String {
    match source.rsplit('/').find(|c| !c.is_empty() && *c != "." && *c != "..") {
        Some(c) => c.to_string(),
        None => crate::mount::F2FS_NAME.to_string(),
    }
}

/// Withdraws one mount's published entries, given its directory name.
pub type Teardown = fn(&str);

/// The withdrawal the trees installed.
///
/// A mount publishes into `/proc/fs` and `/sys/fs` from the code that mounts
/// it, which holds both this crate and those trees. Unmount has no such
/// place: it arrives at this filesystem's own superblock operations, which
/// cannot name a pseudo-filesystem. So the integrator leaves the withdrawal
/// here on the way in, and unmount runs it on the way out — the alternative
/// is a directory per mount that accumulates for the life of the boot and
/// reports on a volume nobody can reach.
static TEARDOWN: sync::Spinlock<Option<Teardown>, sync::TaskList> = sync::Spinlock::new(None);

/// Install the withdrawal. Called once, where the surfaces are published.
/// # C: O(1)
pub fn set_teardown(f: Teardown) { *TEARDOWN.lock() = Some(f); }

/// Withdraw one mount's entries. Does nothing when nothing was published,
/// which is the state of every mount in a build that publishes no surfaces.
/// # C: cost of the withdrawal
pub fn run_teardown(dev: &str) {
    let f = *TEARDOWN.lock();
    if let Some(f) = f { f(dev); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scalar_is_one_decimal_line() {
        assert_eq!(line_u64(0), b"0\n");
        assert_eq!(line_u64(4096), b"4096\n");
    }

    #[test]
    fn a_flag_word_is_bare_lowercase_hex() {
        assert_eq!(line_hex(0), b"0\n");
        assert_eq!(line_hex(0x1f), b"1f\n");
    }

    /// The mount directory's name must be a single component: a source path
    /// used whole would create a directory chain, and the withdraw at unmount
    /// would not match what the mount published.
    #[test]
    fn the_mount_directory_is_the_sources_last_component() {
        assert_eq!(dev_id("/dev/vda"), "vda");
        assert_eq!(dev_id("/dev/mapper/root"), "root");
        assert_eq!(dev_id("vdb"), "vdb");
        assert_eq!(dev_id("/dev/vdc/"), "vdc");
    }

    /// A source that names no component at all still gets a directory rather
    /// than an empty name the tree would refuse.
    #[test]
    fn a_source_with_no_component_falls_back_to_the_filesystem_name() {
        assert_eq!(dev_id("/"), "f2fs");
        assert_eq!(dev_id(""), "f2fs");
        assert_eq!(dev_id("/../."), "f2fs");
    }

    /// Unmount must be able to withdraw what mount published, or a directory
    /// reporting on an unreachable volume outlives it.
    #[test]
    fn the_teardown_hook_runs_for_the_mount_it_is_given() {
        use core::sync::atomic::{AtomicU32, Ordering};
        static SEEN: AtomicU32 = AtomicU32::new(0);
        fn note(dev: &str) { if dev == "vdz" { SEEN.fetch_add(1, Ordering::Relaxed); } }
        set_teardown(note);
        run_teardown("vdz");
        run_teardown("other");
        assert_eq!(SEEN.load(Ordering::Relaxed), 1);
    }
}
