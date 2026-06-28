//! inode-16§2 symlink content path: `readlink` (raw storage primitive,
//! `EINVAL` on a non-symlink) vs `get_link` (the VFS resolution entry the path
//! walker + `readlink(2)` call). Mirrors Linux `fs/namei.c` `get_link()`: the
//! inline `i_link` fast path is consulted BEFORE the per-inode `readlink` op.
//! Driven over minimal `Inode` impls, no QEMU.

use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

/// Non-symlink (regular file): no inline link, no `readlink` override.
struct NonLink;
impl Inode for NonLink {
    fn ino(&self) -> vfs::Ino { 2 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// Symlink whose target lives in a per-inode `readlink` store (ext4-style:
/// read from backing storage on demand). `get_link` must delegate here.
struct StoreLink(&'static [u8]);
impl Inode for StoreLink {
    fn ino(&self) -> vfs::Ino { 3 }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { self.0.len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> { Ok(self.0.to_vec()) }
}

/// Symlink whose target is stored INLINE in the inode (Linux `inode->i_link`
/// fast symlink). Only `i_link` is implemented — NO `readlink` override.
struct InlineLink(&'static [u8]);
impl Inode for InlineLink {
    fn ino(&self) -> vfs::Ino { 4 }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { self.0.len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn i_link(&self) -> Option<&[u8]> { Some(self.0) }
}

#[test]
fn readlink_on_non_symlink_is_einval() {
    // Linux readlink(2): -EINVAL when the final component is not a symlink.
    assert_eq!(NonLink.readlink().unwrap_err(), VfsError::Einval);
    assert_eq!(NonLink.get_link().unwrap_err(), VfsError::Einval);
}

#[test]
fn get_link_delegates_to_readlink_store() {
    // Backend overriding only `readlink`: `get_link` must surface the same
    // raw bytes (no inline body present, so it falls through to readlink).
    let s = StoreLink(b"target/path");
    assert_eq!(s.readlink().unwrap(), b"target/path");
    assert_eq!(s.get_link().unwrap(), b"target/path");
    assert!(s.i_link().is_none());
}

#[test]
fn get_link_prefers_inline_i_link() {
    // Linux `get_link()` checks `READ_ONCE(inode->i_link)` BEFORE the
    // `i_op->get_link`/readlink op. A fast symlink exposing only `i_link`
    // must resolve through `get_link` — the default `readlink` stays EINVAL,
    // proving the inline fast path (not readlink) produced the bytes.
    let l = InlineLink(b"/etc/passwd");
    assert_eq!(l.i_link(), Some(&b"/etc/passwd"[..]));
    assert_eq!(l.get_link().unwrap(), b"/etc/passwd");
    // The inline backend leaves `readlink` at its EINVAL default, so the
    // bytes provably came from the `i_link` fast path, not `readlink`.
    assert_eq!(l.readlink().unwrap_err(), VfsError::Einval);
}

#[test]
fn raw_target_is_not_followed() {
    // `readlink`/`get_link` return the LITERAL target — the walker (not these
    // accessors) does any recursive follow. An absolute target comes back
    // verbatim, leading slash intact.
    let abs = StoreLink(b"/abs/dst");
    assert_eq!(abs.get_link().unwrap(), b"/abs/dst");
    let rel = InlineLink(b"../rel/dst");
    assert_eq!(rel.get_link().unwrap(), b"../rel/dst");
}
