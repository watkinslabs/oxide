// `file_operations` (Linux `struct file_operations`) per `16§2` — the per-open
// DATA-PATH vtable hung off a `struct Inode` as `i_fop`. Split out of the old
// god-trait `Inode`: an inode is now CONCRETE state (`inode.rs`) plus two
// behaviour vtables, `i_op` ([`crate::inode_ops::InodeOps`]) for the
// namespace/metadata ops and `i_fop` (here) for read/write/poll/iterate.
//
// Every method takes `&self` (the ops object, usually a ZST or a small shared
// driver state) AND `inode: &Inode` (the concrete inode the op acts on), so one
// `Arc<dyn FileOps>` instance serves every inode of a backend without per-inode
// closures. Default bodies are the Linux "no f_op installed" behaviour
// (`EISDIR` on a directory read, `EINVAL` otherwise; always-ready poll), so a
// backend overrides only what it implements.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::inode::{Inode, no_data_op_errno, POLL_IN, POLL_OUT};
use crate::types::{FileType, KResult};

/// `file_operations` — the inode's `i_fop` data-path vtable. # Lk: callers hold
/// no inode lock; an op serialises its own backend state.
pub trait FileOps: Send + Sync {
    /// `f_op->read` — read into `buf` at byte offset `off`; `0` = EOF. Default
    /// binds to `S_IFMT`: `EISDIR` for a directory, `EINVAL` otherwise (Linux
    /// `vfs_read` with no `read`/`read_iter`). # C: backend-dependent
    fn read(&self, inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(no_data_op_errno(inode.file_type()))
    }

    /// `f_op->write` — write `buf` at byte offset `off`. Default `EISDIR`/`EINVAL`
    /// per `S_IFMT` (Linux `vfs_write`). # C: backend-dependent
    fn write(&self, inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(no_data_op_errno(inode.file_type()))
    }

    /// Non-blocking read (`O_NONBLOCK`, `15§5`): `EAGAIN` rather than park.
    /// Default forwards to [`Self::read`] (correct for never-blocking inodes —
    /// regular files, tmpfs, procfs); pipes/ttys/sockets override. # C: backend
    fn read_nonblock(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read(inode, off, buf)
    }

    /// Non-blocking write. Default forwards to [`Self::write`]. # C: backend
    fn write_nonblock(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write(inode, off, buf)
    }

    /// `f_op->iterate`/`dir_emit` — emit child entries from cookie `off`. The
    /// callback gets `(ino, next_off, name, file_type)` and returns `false` to
    /// stop. Default `ENOTDIR` (Linux non-directory). # C: backend-dependent
    fn iterate(
        &self,
        _inode: &Inode,
        _off: u64,
        _f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        Err(crate::types::VfsError::Enotdir)
    }

    /// `f_op->poll` readiness bitmask (`POLL_*`). Default always readable +
    /// writable (synthetic/static inodes never block). # C: O(1)
    fn poll(&self, _inode: &Inode) -> u32 { POLL_IN | POLL_OUT }

    /// Position-aware poll — readiness given the caller's per-fd cursor `pos`
    /// (append-only streams: `/dev/kmsg`). Default forwards to [`Self::poll`].
    /// # C: O(1)
    fn poll_file(&self, inode: &Inode, _pos: u64) -> u32 { self.poll(inode) }

    /// `MAP_SHARED` page-cache frame for page-aligned file offset `off`. Default
    /// forwards through the inode's `i_mapping` (one per-inode address space);
    /// `None` → the fault handler copies via `read` into a private frame.
    /// # C: O(log N_pages)
    fn mmap_shared_frame(&self, inode: &Inode, off: u64) -> Option<u64> {
        inode.i_mapping().and_then(|m| m.shared_frame(off))
    }

    /// `f_op->open` — open-time hook fired after path resolution, before the
    /// `File`/fd is built; a driver may reject the open. Default `Ok`. # C: O(1)
    fn on_open(&self, _inode: &Inode) -> KResult<()> { Ok(()) }

    /// `f_op->release` — last-close hook (final fd of an open description
    /// drops). MUST NOT panic/block (runs from `File` Drop). # C: O(1)
    fn on_release(&self, _inode: &Inode) {}

    /// `f_op->flush` — per-`close(2)` hook on EVERY fd close (not only the
    /// last). MUST NOT panic/block. # C: O(1)
    fn on_flush(&self, _inode: &Inode) {}

    /// `show_fdinfo` extra lines appended to `/proc/<pid>/fdinfo/<n>` after the
    /// generic `pos/flags/mnt_id/ino` (pidfd `Pid:`/`NSpid:`). Default none.
    /// # C: O(1)
    fn fdinfo_extra(&self, _inode: &Inode, _out: &mut Vec<u8>) {}
}

/// The "no f_op installed" default vtable (Linux `def_blk_fops`-less inode):
/// every method takes its trait default. Bound as `i_fop` on inodes whose data
/// path is the generic `S_IFMT` behaviour (directories with only `i_op->lookup`,
/// metadata-only pseudo nodes). # C: O(1)
pub struct DefaultFileOps;
impl FileOps for DefaultFileOps {}

/// Shared `Arc<dyn FileOps>` for the default vtable (one allocation per call;
/// the vtable is a ZST so the `Arc` is just the refcount box). # C: O(1)
pub fn default_file_ops() -> Arc<dyn FileOps> { Arc::new(DefaultFileOps) }
