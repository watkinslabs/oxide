//! inode-16§2 symlink content path: `readlink` (raw storage primitive,
//! `EINVAL` on a non-symlink) vs `get_link` (the VFS resolution entry the path
//! walker + `readlink(2)` call). Mirrors Linux `fs/namei.c` `get_link()`: the
//! inline `i_link` fast path is consulted BEFORE the per-inode `readlink` op.
//! Driven over `InodeBuilder` fixtures, no QEMU.

use std::sync::Arc;

use vfs::inode::{Inode, InodeBuilder};
use vfs::inode_ops::InodeOps;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef, KResult};

/// Non-symlink (regular file): no inline link, no `readlink` override.
fn non_link() -> InodeRef {
    InodeBuilder::new(2, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

/// Per-inode `readlink` store (ext4-style: read target from backing storage on
/// demand), held in `i_private`.
struct StoreLinkData(Vec<u8>);
struct StoreLinkOps;
impl InodeOps for StoreLinkOps {
    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        Ok(inode.private::<StoreLinkData>().map(|d| d.0.clone()).unwrap_or_default())
    }
}

/// Symlink whose target lives in a per-inode `readlink` store; `get_link` must
/// delegate here (no inline `i_link`).
fn store_link(target: &'static [u8]) -> InodeRef {
    InodeBuilder::new(3, mk_mode(FileType::Symlink, 0o777), Arc::new(StoreLinkOps), default_file_ops())
        .size(target.len() as u64)
        .private(Arc::new(StoreLinkData(target.to_vec())))
        .build()
}

/// Symlink whose target is stored INLINE in the inode (Linux `inode->i_link`
/// fast symlink). Only `i_link` is set — NO `readlink` override (default EINVAL).
fn inline_link(target: &'static [u8]) -> InodeRef {
    InodeBuilder::new(4, mk_mode(FileType::Symlink, 0o777), default_inode_ops(), default_file_ops())
        .size(target.len() as u64)
        .link(target.to_vec().into_boxed_slice())
        .build()
}

#[test]
fn readlink_on_non_symlink_is_einval() {
    // Linux readlink(2): -EINVAL when the final component is not a symlink.
    let n = non_link();
    assert_eq!(n.readlink().unwrap_err(), vfs::VfsError::Einval);
    assert_eq!(n.get_link().unwrap_err(), vfs::VfsError::Einval);
}

#[test]
fn get_link_delegates_to_readlink_store() {
    // Backend overriding only `readlink`: `get_link` must surface the same
    // raw bytes (no inline body present, so it falls through to readlink).
    let s = store_link(b"target/path");
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
    let l = inline_link(b"/etc/passwd");
    assert_eq!(l.i_link(), Some(&b"/etc/passwd"[..]));
    assert_eq!(l.get_link().unwrap(), b"/etc/passwd");
    // The inline backend leaves `readlink` at its EINVAL default, so the
    // bytes provably came from the `i_link` fast path, not `readlink`.
    assert_eq!(l.readlink().unwrap_err(), vfs::VfsError::Einval);
}

#[test]
fn raw_target_is_not_followed() {
    // `readlink`/`get_link` return the LITERAL target — the walker (not these
    // accessors) does any recursive follow. An absolute target comes back
    // verbatim, leading slash intact.
    let abs = store_link(b"/abs/dst");
    assert_eq!(abs.get_link().unwrap(), b"/abs/dst");
    let rel = inline_link(b"../rel/dst");
    assert_eq!(rel.get_link().unwrap(), b"../rel/dst");
}
