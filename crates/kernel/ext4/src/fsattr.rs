//! What this filesystem publishes into `/sys/fs`, in terms that tree does not
//! have to know about.
//!
//! An entry is a name, a permission and something that renders bytes when it
//! is read. The tree hosting it owns the directory, the inode and the read
//! plumbing; the filesystem owns the value. Describing an entry as data keeps
//! that split honest — this crate never names a `/sys` type, and `/sys` never
//! names one of this crate's.
//!
//! Every renderer here reads the LIVE mount. An attribute answering from bytes
//! captured at mount would report the state at mount forever, and nothing in a
//! reader could tell the difference.
//!
//! Everything published is read-only. The reference's writable attributes are
//! the allocator's tuning, the inode readahead window and the reserve — knobs
//! whose machinery this build does not have, and a knob that accepted a value
//! nothing reads would be worse than an absent one.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::KResult;

/// Renders an entry's current bytes.
pub type ShowFn = Arc<dyn Fn() -> KResult<Vec<u8>> + Send + Sync>;

/// Permission of a report — everything a reader may look at, and nothing more.
pub const RO: u16 = 0o444;

/// One entry to publish, relative to the filesystem's own directory.
pub struct Attr {
    /// Directory under the filesystem's own, empty for a direct child.
    pub dir:  String,
    pub name: &'static str,
    pub mode: u16,
    pub show: ShowFn,
}

impl Attr {
    /// A read-only entry. # C: O(1)
    pub fn ro(dir: &str, name: &'static str, show: ShowFn) -> Attr {
        Attr { dir: dir.to_string(), name, mode: RO, show }
    }
}

/// One decimal number and a newline — the shape a sysfs scalar takes.
/// # C: O(1)
pub fn line_u64(v: u64) -> Vec<u8> { format!("{v}\n").into_bytes() }

/// A string and a newline. # C: O(len)
pub fn line_str(s: &str) -> Vec<u8> { format!("{s}\n").into_bytes() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scalar_is_one_decimal_line() {
        assert_eq!(line_u64(0), b"0\n");
        assert_eq!(line_u64(4096), b"4096\n");
    }

    #[test]
    fn a_word_is_one_line() { assert_eq!(line_str("supported"), b"supported\n"); }
}
