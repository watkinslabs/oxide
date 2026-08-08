//! `/sys/kernel/mm/hugepages` — the per-granule view of the huge-page pool.
//!
//! One directory per granule the pool serves, each carrying the same six
//! attributes. `nr_hugepages` and `nr_overcommit_hugepages` are writable and
//! size the pool; the other four report what it currently holds. Every value
//! is read live from the pool at open time, so nothing here can drift from it.
//!
//! `/proc/sys/vm/nr_hugepages` is the SAME knob for the default granule — the
//! reference has both spellings for the same reason, and both reach the one
//! pool rather than each keeping a number of their own.

use alloc::sync::Arc;

use pmm::hugetlb::{self, HugePageSize};
use vfs::{mk_mode, FileOps, FileType, Ino, Inode, InodeBuilder, KResult, VfsError};

use crate::{read_window, register, register_dir, RO_PERM, RW_PERM};

/// Which pool number one attribute file shows.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Attr { Nr, Free, Resv, Surplus, Overcommit }

impl Attr {
    /// # C: O(1)
    fn read(self, size: HugePageSize) -> u64 {
        match self {
            Attr::Nr         => hugetlb::nr_hugepages(size),
            Attr::Free       => hugetlb::free_hugepages(size),
            Attr::Resv       => hugetlb::resv_hugepages(size),
            Attr::Surplus    => hugetlb::surplus_hugepages(size),
            Attr::Overcommit => hugetlb::nr_overcommit_hugepages(size),
        }
    }
    /// The attributes an operator may set. The four that merely report what
    /// the pool holds are read-only, because a write to them would name a
    /// state the pool cannot be put into directly.
    /// # C: O(1)
    fn writable(self) -> bool { matches!(self, Attr::Nr | Attr::Overcommit) }
    /// # C: O(1)
    fn write(self, size: HugePageSize, v: u64) {
        match self {
            Attr::Nr         => { hugetlb::set_nr_hugepages(size, v); }
            Attr::Overcommit => hugetlb::set_nr_overcommit_hugepages(size, v),
            _ => {}
        }
    }
    /// # C: O(1)
    fn name(self) -> &'static str {
        match self {
            Attr::Nr         => "nr_hugepages",
            Attr::Free       => "free_hugepages",
            Attr::Resv       => "resv_hugepages",
            Attr::Surplus    => "surplus_hugepages",
            Attr::Overcommit => "nr_overcommit_hugepages",
        }
    }
}

struct PoolAttr { attr: Attr, size: HugePageSize }

impl FileOps for PoolAttr {
    /// kernfs / sysfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }

    /// # C: O(1)
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = alloc::format!("{}\n", self.attr.read(self.size)).into_bytes();
        Ok(read_window(&body, off, buf))
    }

    /// A write sizes the pool; the value read back afterwards is what the pool
    /// actually reached, which may be less than what was asked for.
    /// # C: O(|delta| * pages)
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        if !self.attr.writable() { return Err(VfsError::Erofs); }
        let v = parse_count(buf).ok_or(VfsError::Einval)?;
        self.attr.write(self.size, v);
        Ok(buf.len())
    }
}

/// A decimal count, with leading and trailing whitespace ignored the way every
/// sysfs numeric attribute does. Anything else is `EINVAL` rather than a
/// partial read that would silently size the pool to a number nobody typed.
/// # C: O(len)
fn parse_count(buf: &[u8]) -> Option<u64> {
    let t = buf.iter().position(|c| !c.is_ascii_whitespace())?;
    let body = &buf[t..];
    let end = body.iter().position(|c| c.is_ascii_whitespace()).unwrap_or(body.len());
    let digits = &body[..end];
    if digits.is_empty() { return None; }
    let mut n: u64 = 0;
    for &c in digits {
        if !c.is_ascii_digit() { return None; }
        n = n.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(n)
}

/// Inode number of one attribute: the granule in the middle byte, the
/// attribute in the low one, so no two leaves of the tree can collide.
/// # C: O(1)
fn attr_ino(size: HugePageSize, attr: Attr) -> Ino {
    let g = match size { HugePageSize::Huge2M => 0u64, HugePageSize::Huge1G => 1 };
    crate::ids::HUGEPAGES_ATTR | (g << 8) | attr as u64
}

/// Directory name the reference gives a granule: its size in KiB.
/// # C: O(1)
fn dir_name(size: HugePageSize) -> alloc::string::String {
    alloc::format!("hugepages-{}kB", size.bytes() / 1024)
}

fn make_attr_inode(size: HugePageSize, attr: Attr) -> vfs::InodeRef {
    let perm = if attr.writable() { RW_PERM } else { RO_PERM };
    InodeBuilder::new(attr_ino(size, attr), mk_mode(FileType::Regular, perm),
        crate::kobject::attr_inode_ops(), Arc::new(PoolAttr { attr, size }))
        .build()
}

/// Every granule the pool serves gets a directory; every directory gets the
/// same six attributes. # C: O(1)
pub fn init() {
    register_dir("/sys/kernel/mm/hugepages");
    for size in [HugePageSize::Huge2M, HugePageSize::Huge1G] {
        let dir = alloc::format!("/sys/kernel/mm/hugepages/{}", dir_name(size));
        register_dir(&dir);
        for attr in [Attr::Nr, Attr::Free, Attr::Resv, Attr::Surplus, Attr::Overcommit] {
            register(&alloc::format!("{dir}/{}", attr.name()), make_attr_inode(size, attr));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_granule_directory_is_named_for_its_size_in_kib() {
        assert_eq!(dir_name(HugePageSize::Huge2M), "hugepages-2048kB");
        assert_eq!(dir_name(HugePageSize::Huge1G), "hugepages-1048576kB");
    }

    #[test]
    fn only_the_two_sizing_attributes_are_writable() {
        assert!(Attr::Nr.writable());
        assert!(Attr::Overcommit.writable());
        for a in [Attr::Free, Attr::Resv, Attr::Surplus] {
            assert!(!a.writable(), "{} reports the pool, it does not set it", a.name());
        }
    }

    #[test]
    fn no_two_attributes_of_the_tree_share_an_inode_number() {
        let mut seen = alloc::vec::Vec::new();
        for size in [HugePageSize::Huge2M, HugePageSize::Huge1G] {
            for attr in [Attr::Nr, Attr::Free, Attr::Resv, Attr::Surplus, Attr::Overcommit] {
                let n = attr_ino(size, attr);
                assert!(!seen.contains(&n), "inode {n:#x} claimed twice");
                seen.push(n);
            }
        }
        assert_eq!(seen.len(), 10);
    }

    #[test]
    fn a_count_is_read_with_surrounding_whitespace_ignored() {
        assert_eq!(parse_count(b"8"), Some(8));
        assert_eq!(parse_count(b"  16\n"), Some(16));
        assert_eq!(parse_count(b"0\n"), Some(0));
    }

    #[test]
    fn anything_that_is_not_a_count_is_refused() {
        for b in [b"" as &[u8], b"\n", b"  ", b"-1", b"12x", b"0x10", b"abc"] {
            assert_eq!(parse_count(b), None, "{:?} must not size the pool", core::str::from_utf8(b));
        }
    }

    #[test]
    fn each_attribute_reads_the_pool_rather_than_a_copy() {
        // Nothing has sized the pool in a hosted build, so every number is the
        // pool's own zero — the point is that the value comes FROM the pool.
        let s = HugePageSize::Huge2M;
        assert_eq!(Attr::Nr.read(s), pmm::hugetlb::nr_hugepages(s));
        assert_eq!(Attr::Free.read(s), pmm::hugetlb::free_hugepages(s));
        assert_eq!(Attr::Resv.read(s), pmm::hugetlb::resv_hugepages(s));
        assert_eq!(Attr::Surplus.read(s), pmm::hugetlb::surplus_hugepages(s));
        assert_eq!(Attr::Overcommit.read(s), pmm::hugetlb::nr_overcommit_hugepages(s));
    }

    #[test]
    fn the_overcommit_attribute_writes_through_to_the_pool() {
        let s = HugePageSize::Huge1G;
        let before = pmm::hugetlb::nr_overcommit_hugepages(s);
        Attr::Overcommit.write(s, before + 3);
        assert_eq!(pmm::hugetlb::nr_overcommit_hugepages(s), before + 3);
        Attr::Overcommit.write(s, before);
    }
}
