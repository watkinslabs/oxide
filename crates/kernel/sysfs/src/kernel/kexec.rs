// The three `/sys/kernel/kexec_*` attributes.
//
// These are what a service manager reads before it decides whether a reboot
// request can be answered by jumping straight into an already-staged kernel,
// and what a crash-dump tool reads to size — and shrink — the memory that has
// been set aside for a kernel that only runs after a panic.
//
// Every decision here is ungated and host-tested: the two loaded flags are one
// character each, and reporting the wrong one makes a manager either fall back
// to a full firmware reboot it did not need or jump into a slot holding nothing.

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, FileOps, FileType, Ino, Inode, InodeBuilder, KResult, VfsError};

use crate::{read_window, register, RO_PERM, RW_PERM};

/// The three attribute inodes.
const INO_LOADED: Ino = crate::ids::KEXEC_LOADED;
const INO_CRASH_LOADED: Ino = crate::ids::KEXEC_CRASH_LOADED;
const INO_CRASH_SIZE: Ino = crate::ids::KEXEC_CRASH_SIZE;

/// A boolean attribute's body: one decimal digit and a newline.
///
/// The trailing newline is not decoration — a reader that compares the whole
/// body against `"1"` must see it, and one that parses a decimal must not trip
/// over anything else.
/// # C: O(1)
pub fn flag_body(set: bool) -> Vec<u8> {
    alloc::vec![if set { b'1' } else { b'0' }, b'\n']
}

/// A byte-count attribute's body. # C: O(1)
pub fn size_body(bytes: u64) -> Vec<u8> { alloc::format!("{bytes}\n").into_bytes() }

/// Parse a byte count written to `kexec_crash_size`.
///
/// Decimal, or hexadecimal behind `0x`. A tool computing a new reservation
/// prints it either way, and a parser that took `0x2000000` as decimal `0`
/// would shrink the region to nothing without reporting an error.
/// # C: O(len)
pub fn parse_size(src: &[u8]) -> Option<u64> {
    let text = core::str::from_utf8(src).ok()?.trim();
    if text.is_empty() { return None; }
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse::<u64>().ok(),
    }
}

/// Bytes currently reserved for a crash kernel. # C: O(1)
pub fn crash_size() -> u64 { kexec::crash_size() }

/// Apply a write to `kexec_crash_size`: parse the count, then shrink the
/// reservation to it.
///
/// A malformed count is EINVAL and changes nothing. The reservation itself
/// decides whether the new size is reachable — only a reservation that exists
/// can be shrunk, and it can only ever get smaller.
/// # C: O(len + pages released)
pub fn write_crash_size(src: &[u8]) -> KResult<()> {
    let want = parse_size(src).ok_or(VfsError::Einval)?;
    kexec::crashk::shrink::shrink(want).map_err(shrink_error)
}

/// Map a refused shrink onto the error the writer collects.
///
/// A region with an image staged in it answers ENOENT rather than EINVAL: the
/// number the caller wrote was fine, and its remedy is to unload the image
/// first, which is a different action from picking another size.
/// # C: O(1)
pub fn shrink_error(err: kexec::crashk::shrink::ShrinkError) -> VfsError {
    match err {
        kexec::crashk::shrink::ShrinkError::Loaded => VfsError::Enoent,
        kexec::crashk::shrink::ShrinkError::Grow
        | kexec::crashk::shrink::ShrinkError::NoRegion => VfsError::Einval,
    }
}

struct FlagOps { get: fn() -> bool }
impl FileOps for FlagOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        Ok(read_window(&flag_body((self.get)()), off, buf))
    }
    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

struct CrashSizeOps;
impl FileOps for CrashSizeOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        Ok(read_window(&size_body(crash_size()), off, buf))
    }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        write_crash_size(buf)?;
        Ok(buf.len())
    }
}

fn make_flag_inode(ino: Ino, get: fn() -> bool) -> vfs::InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, RO_PERM),
        crate::kobject::attr_inode_ops(), Arc::new(FlagOps { get }))
        .build()
}

fn make_crash_size_inode() -> vfs::InodeRef {
    InodeBuilder::new(INO_CRASH_SIZE, mk_mode(FileType::Regular, RW_PERM),
        crate::kobject::attr_inode_ops(), Arc::new(CrashSizeOps))
        .build()
}

/// Register the `/sys/kernel/kexec_*` attributes. # C: O(1)
pub fn init() {
    register("/sys/kernel/kexec_loaded", make_flag_inode(INO_LOADED, kexec::kexec_loaded));
    register("/sys/kernel/kexec_crash_loaded",
        make_flag_inode(INO_CRASH_LOADED, kexec::kexec_crash_loaded));
    register("/sys/kernel/kexec_crash_size", make_crash_size_inode());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_loaded_flag_is_one_digit_and_a_newline() {
        assert_eq!(flag_body(false), b"0\n".to_vec());
        assert_eq!(flag_body(true), b"1\n".to_vec());
    }

    #[test]
    fn the_two_loaded_flags_report_their_own_slot() {
        // With nothing staged both are zero, and each reads the slot it names —
        // a crash image staged into the panic slot must not make the reboot
        // slot claim a kernel a `reboot` would then fail to find.
        let loaded = make_flag_inode(INO_LOADED, kexec::kexec_loaded);
        let crash = make_flag_inode(INO_CRASH_LOADED, kexec::kexec_crash_loaded);
        let mut buf = [0u8; 8];
        let n = loaded.read(0, &mut buf).expect("read kexec_loaded");
        assert_eq!(&buf[..n], flag_body(kexec::kexec_loaded()).as_slice());
        let n = crash.read(0, &mut buf).expect("read kexec_crash_loaded");
        assert_eq!(&buf[..n], flag_body(kexec::kexec_crash_loaded()).as_slice());
        assert_ne!(INO_LOADED, INO_CRASH_LOADED);
    }

    #[test]
    fn the_reserved_size_is_reported_in_decimal_bytes() {
        assert_eq!(size_body(0), b"0\n".to_vec());
        assert_eq!(size_body(256 * 1024 * 1024), b"268435456\n".to_vec());
        let inode = make_crash_size_inode();
        let mut buf = [0u8; 32];
        let n = inode.read(0, &mut buf).expect("read kexec_crash_size");
        assert_eq!(&buf[..n], size_body(kexec::crash_size()).as_slice());
    }

    #[test]
    fn a_size_write_is_accepted_as_decimal_or_hexadecimal() {
        assert_eq!(parse_size(b"0"), Some(0));
        assert_eq!(parse_size(b"268435456\n"), Some(268_435_456));
        assert_eq!(parse_size(b"  1048576  "), Some(1_048_576));
        // Taking this as decimal yields zero, which reads as "release the whole
        // reservation" instead of "shrink it to 32 MiB".
        assert_eq!(parse_size(b"0x2000000\n"), Some(0x200_0000));
        assert_eq!(parse_size(b"0X10"), Some(16));
    }

    #[test]
    fn a_malformed_size_write_is_refused_and_changes_nothing() {
        assert_eq!(parse_size(b""), None);
        assert_eq!(parse_size(b"\n"), None);
        assert_eq!(parse_size(b"-1"), None);
        assert_eq!(parse_size(b"12M"), None);
        assert_eq!(parse_size(b"0xzz"), None);
        let before = kexec::crash_size();
        assert_eq!(write_crash_size(b"12M"), Err(VfsError::Einval));
        assert_eq!(kexec::crash_size(), before);
    }

    #[test]
    fn a_refused_shrink_reports_why_it_was_refused() {
        use kexec::crashk::shrink::ShrinkError;
        // Two different remedies, so two different errors: a caller told
        // EINVAL retries with another number, and one told ENOENT unloads the
        // image it forgot was staged.
        assert_eq!(shrink_error(ShrinkError::Loaded), VfsError::Enoent);
        assert_eq!(shrink_error(ShrinkError::Grow), VfsError::Einval);
        assert_eq!(shrink_error(ShrinkError::NoRegion), VfsError::Einval);
        // With nothing reserved, every well-formed write is refused and the
        // reported size does not move.
        assert_eq!(kexec::crash_size(), 0);
        assert_eq!(write_crash_size(b"0x1000000"), Err(VfsError::Einval));
        assert_eq!(kexec::crash_size(), 0);
    }

    #[test]
    fn the_two_flag_attributes_are_read_only_and_the_size_attribute_is_not() {
        // A writable loaded flag would invite a caller to "clear" a staged
        // image through a file that cannot free one.
        assert_eq!(RO_PERM, 0o444);
        assert_eq!(RW_PERM, 0o644);
        let loaded = make_flag_inode(INO_LOADED, kexec::kexec_loaded);
        assert_eq!(loaded.write(0, b"1"), Err(VfsError::Erofs));
    }
}
