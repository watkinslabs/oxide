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
//
// Module manifest:
//   ioctl.rs  — `unlocked_ioctl` command/reply shapes.
//   dir.rs    — directory-iteration shapes (`DirEmit`, `DirContext`) and the
//               `SEEK_HOLE`/`SEEK_DATA` selector.
//   stream.rs — the default vectored-write engine backends reuse.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::file::File;
use crate::inode::{Inode, no_data_op_errno, POLL_IN, POLL_OUT};
use crate::poll_subs::PollSubscribers;
use crate::types::{FileType, KResult, VfsError};

mod ioctl;
pub use ioctl::{FileIoctlCmd, FileIoctlReply, IoctlIntCmd};

mod dir;
pub use dir::{DirContext, DirEmit, HoleOrData};
#[cfg(feature = "debug-getdents")]
pub use dir::DirDebugBackend;

mod stream;
pub use stream::{stream_write_iter_file, stream_write_iter_with};

/// `file_operations` — the inode's `i_fop` data-path vtable. # Lk: callers hold
/// no inode lock; an op serialises its own backend state.
pub trait FileOps: Send + Sync {
    /// `f_op->read` — read into `buf` at byte offset `off`; `0` = EOF. Default
    /// binds to `S_IFMT`: `EISDIR` for a directory, `EINVAL` otherwise (Linux
    /// `vfs_read` with no `read`/`read_iter`). # C: backend-dependent
    fn read(&self, inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(no_data_op_errno(inode.file_type()))
    }

    /// `f_op->read` with access to the open file description. Backends with
    /// per-open state override this; the default preserves inode-only drivers.
    /// # C: backend-dependent
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read(file.inode(), off, buf)
    }

    /// `f_op->write` — write `buf` at byte offset `off`. Default `EISDIR`/`EINVAL`
    /// per `S_IFMT` (Linux `vfs_write`). # C: backend-dependent
    fn write(&self, inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(no_data_op_errno(inode.file_type()))
    }

    /// `f_op->write` with access to the open file description. Backends whose
    /// write target is per-open state (`/dev/fuse`: the reply channel is keyed by
    /// the open `File`) override this; the default preserves inode-only drivers.
    /// # C: backend-dependent
    fn write_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write(file.inode(), off, buf)
    }

    /// Non-blocking write with access to the open file description. Default
    /// forwards to [`Self::write_nonblock`]. # C: backend-dependent
    fn write_nonblock_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write_nonblock(file.inode(), off, buf)
    }

    /// `f_op->write` carrying the caller's MORE-DATA hint: `more` says another
    /// buffer follows this one immediately, so a description that forms
    /// network segments may hold these bytes back and coalesce them with the
    /// next write instead of emitting a short segment now.
    ///
    /// Every description-cursor write reaches its backend through here, which
    /// is why the default drops the hint and forwards to the plain blocking /
    /// non-blocking entry: a backend for which "more data follows" changes
    /// nothing — regular files, tmpfs, procfs, pipes, ttys — keeps its existing
    /// behaviour untouched, and only a segment-forming backend overrides.
    /// # C: backend-dependent
    #[inline]
    fn write_more_file(&self, file: &File, off: u64, buf: &[u8], nonblock: bool, more: bool)
        -> KResult<usize>
    {
        let _ = more;
        if nonblock { self.write_nonblock_file(file, off, buf) } else { self.write_file(file, off, buf) }
    }

    /// Non-blocking read (`O_NONBLOCK`, `15§5`): `EAGAIN` rather than park.
    /// Default forwards to [`Self::read`] (correct for never-blocking inodes —
    /// regular files, tmpfs, procfs); pipes/ttys/sockets override. # C: backend
    fn read_nonblock(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read(inode, off, buf)
    }

    /// Non-blocking read with access to the open file description.
    /// # C: backend-dependent
    fn read_nonblock_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read_nonblock(file.inode(), off, buf)
    }

    /// Non-blocking write. Default forwards to [`Self::write`]. # C: backend
    fn write_nonblock(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write(inode, off, buf)
    }

    /// `f_op->write_iter` over one imported iovec array. Message-boundary backends
    /// override this to consume the complete vector as one record. The default
    /// preserves stream/regular-file partial-progress semantics. # C: O(sum lens)
    fn write_iter_file(&self, file: &File, off: u64, bufs: &[&[u8]], nonblock: bool) -> KResult<usize> {
        stream_write_iter_file(self, file, off, bufs, nonblock)
    }

    /// `f_op->iterate_shared` — emit child entries through `ctx`, resuming at the
    /// cursor `ctx.pos` (the readdir cookie). The backend walks its entries from
    /// `ctx.pos`, calling [`DirContext::emit`] per entry with that entry's
    /// `next_pos` cookie; `emit` returns `false` once the actor's buffer is full,
    /// at which point the backend stops. On stop, `ctx.pos` holds the resume
    /// cookie of the LAST emitted entry (Linux: the actor advances `ctx->pos`).
    /// Default `ENOTDIR` (Linux non-directory). # C: backend-dependent
    fn iterate(&self, _inode: &Inode, _ctx: &mut DirContext) -> KResult<()> {
        Err(crate::types::VfsError::Enotdir)
    }

    /// `f_op->iterate_shared(struct file *, struct dir_context *)` — the
    /// FILE-carrying form. Linux hands the open DESCRIPTION to readdir, not the
    /// inode, so a backend can keep per-open cursor state across the paginated
    /// `getdents` calls that make up one listing. A backend whose entries are
    /// inode state only (every synthetic fs, tmpfs, ext4) needs nothing from the
    /// file and inherits the default; FUSE overrides it so the daemon's
    /// `OPENDIR` handle — and therefore the daemon's own cursor — survives from
    /// one page to the next instead of being re-opened and released per call.
    /// # C: backend-dependent
    fn iterate_file(&self, file: &crate::File, ctx: &mut DirContext) -> KResult<()> {
        self.iterate(file.inode(), ctx)
    }

    /// Does [`Self::iterate`] already emit `.` and `..`? Linux makes each
    /// filesystem call `dir_emit_dots` itself; a backend whose entries live on
    /// disk (ext4) or come from a userspace daemon (FUSE) has them already, and
    /// a synthetic backend does not. Default `false` — the VFS synthesises them
    /// (`crate::readdir::readdir_dots`), which is what keeps every synthetic
    /// filesystem from silently shipping dotless directories that break
    /// `ls -a`, `find`, and any `..`-walk. # C: O(1)
    fn iterate_emits_dots(&self) -> bool { false }

    /// `f_op->poll` readiness bitmask (`POLL_*`). Default always readable +
    /// writable (synthetic/static inodes never block). # C: O(1)
    fn poll(&self, _inode: &Inode) -> u32 { POLL_IN | POLL_OUT }

    /// Position-aware poll — readiness given the caller's per-fd cursor `pos`
    /// (append-only streams: `/dev/kmsg`). Default forwards to [`Self::poll`].
    /// # C: O(1)
    fn poll_file(&self, inode: &Inode, _pos: u64) -> u32 { self.poll(inode) }

    /// `f_op->poll` with access to the open file description. Backends with
    /// per-open readiness, such as evdev grabs, override this.
    /// # C: O(1)
    fn poll_open_file(&self, file: &File) -> u32 {
        self.poll_file(file.inode(), file.pos())
    }

    /// Wait source selected while a poll consumer registers this open file.
    /// Most backends use the inode's fixed source; task-relative backends such
    /// as signalfd override this to select the current caller's source.
    /// # C: O(1)
    fn poll_subscribers(&self, file: &File) -> Option<Arc<PollSubscribers>> {
        file.inode().poll_subscribers_arc()
    }

    /// Earliest monotonic deadline at which `poll_open_file` can become ready
    /// without a source notification. Timer-backed files override this so a
    /// poll consumer can arm the scheduler deadline instead of periodically
    /// rescanning. `None` means readiness changes only through notifications.
    /// # C: O(1)
    fn poll_deadline_ns(&self, _file: &File) -> Option<u64> { None }

    /// `file_can_poll` — does this description implement a readiness op?
    /// `epoll_ctl(2)` is the ONLY caller: a target that cannot poll is `EPERM`
    /// there, while `poll(2)`/`select(2)` keep the always-ready default mask
    /// for the same file. Regular files and directories therefore stay usable
    /// with `poll`/`select` and stay rejected by `epoll_ctl`, so an event loop
    /// falls back to blocking I/O instead of watching a descriptor that can
    /// never deliver an edge. Default answers by wait source; backends whose
    /// readiness moves with no subscriber list override to `true`.
    /// # C: O(1)
    fn can_poll(&self, file: &File) -> bool { self.poll_subscribers(file).is_some() }

    /// `f_op->fasync` — backend admission for `FIOASYNC`/`F_SETFL(O_ASYNC)`.
    /// Default means no fasync op installed; async-capable stream backends call
    /// [`File::set_fasync_state`] to link/unlink the open description.
    /// # C: backend-dependent
    fn fasync_file(&self, _fd: i32, _file: &Arc<File>, _on: bool) -> KResult<()> {
        Err(VfsError::Enotty)
    }

    /// Int-valued `f_op->unlocked_ioctl` subset. Default `ENOTTY`; stream and
    /// socket backends override with their queue accounting. # C: backend
    fn ioctl_int(&self, _file: &File, _cmd: IoctlIntCmd) -> KResult<u32> {
        Err(VfsError::Enotty)
    }

    /// `f_op->unlocked_ioctl` for filesystem/file-specific ioctls. Usercopy is
    /// kept in the syscall crate; the backend owns permission and mutation.
    /// # C: backend-dependent
    fn unlocked_ioctl(
        &self,
        _file: &File,
        _idmap: &crate::idmap::Idmap,
        _cred: &crate::namei::Cred,
        _cmd: FileIoctlCmd,
    ) -> KResult<FileIoctlReply> {
        Err(VfsError::Enotty)
    }

    /// `MAP_SHARED` page-cache frame for page-aligned file offset `off`. Default
    /// forwards through the inode's `i_mapping` (one per-inode address space);
    /// `None` → the fault handler copies via `read` into a private frame.
    /// # C: O(log N_pages)
    fn mmap_shared_frame(&self, inode: &Inode, off: u64) -> KResult<Option<crate::SharedFrame>> {
        inode.i_mapping().map_or(Ok(None), |m| m.shared_frame(off))
    }

    /// Whether this file vtable implements Linux `f_op->remap_file_range`.
    /// Default false so VFS admission reports the Linux no-op errno before
    /// calling into a backend. # C: O(1)
    fn supports_remap_file_range(&self) -> bool { false }

    /// Linux `io_is_uring_fops`: `f_op` identity for the one vtable io_uring
    /// installs — rationale in `syscalls::io_uring_identity`. # C: O(1)
    fn is_io_uring(&self) -> bool { false }

    /// `f_op->remap_file_range` — clone/dedupe `[src_off, src_off+len)` from
    /// this source open file into `dst` at `dst_off`. `flags` carries Linux
    /// `REMAP_FILE_*`. Default `Eopnotsupp`; filesystems with reflink support
    /// override both this and [`Self::supports_remap_file_range`]. # C: backend
    fn remap_file_range(&self, src: &File, src_off: u64, dst: &File, dst_off: u64, len: u64, flags: u32) -> KResult<u64> {
        let _ = (src, src_off, dst, dst_off, len, flags);
        Err(VfsError::Eopnotsupp)
    }

    /// `f_op->open` — open-time hook fired after path resolution, before the
    /// `File`/fd is built; a driver may reject the open. Default `Ok`. # C: O(1)
    fn on_open(&self, _inode: &Inode) -> KResult<()> { Ok(()) }

    /// `f_op->open` with access to the just-built open file description. Backends
    /// that initialize Linux `file->private_data` override this; the default
    /// preserves inode-only open hooks.
    /// # C: O(1)
    fn on_open_file(&self, file: &File) -> KResult<()> {
        self.on_open(file.inode())
    }

    /// `f_op->release` — last-close hook (final fd of an open description
    /// drops). MUST NOT panic/block (runs from `File` Drop). # C: O(1)
    fn on_release(&self, _inode: &Inode) {}

    /// Last-close hook with access to the open file description.
    /// # C: O(1)
    fn on_release_file(&self, file: &File) {
        self.on_release(file.inode())
    }

    /// `f_op->flush` — per-`close(2)` hook on EVERY fd close (not only the
    /// last). Its errno is returned by `close(2)` after the fd table entry has
    /// already been removed. # C: O(1)
    fn on_flush(&self, _inode: &Inode) -> KResult<()> { Ok(()) }

    /// `f_op->flush` with access to the open file description. Backends whose
    /// flush target is per-open state override this; default preserves
    /// inode-only drivers. # C: O(1)
    fn on_flush_file(&self, file: &File) -> KResult<()> {
        self.on_flush(file.inode())
    }

    /// `f_op->fsync` (Linux `vfs_fsync_range`): flush this description's
    /// backing store. `datasync` selects `fdatasync(2)` semantics — data plus
    /// only the metadata a reader needs to see it (the size), skipping
    /// timestamps.
    ///
    /// The default reproduces which Linux `file_operations` install an `fsync`
    /// slot at all, because `vfs_fsync_range` returns `EINVAL` for the ones
    /// that do not. Byte-addressable descriptions (regular file, directory,
    /// block device) get `noop_fsync` here and the caller then runs the
    /// page-cache / journal flush; every stream or anon description — pipe and
    /// FIFO (`pipefifo_fops`), socket (`socket_file_ops`), eventfd / epoll /
    /// timerfd / signalfd / inotify / userfaultfd (anon inodes), and character
    /// devices (`memory_fops`, `tty_fops`) — has no `fsync` slot and is
    /// `EINVAL`. A backend with real per-open flush state overrides this.
    /// # C: O(1)
    fn fsync(&self, file: &File, _datasync: bool) -> KResult<()> {
        match file.inode().file_type() {
            FileType::Regular | FileType::Directory | FileType::BlockDev => Ok(()),
            _ => Err(VfsError::Einval),
        }
    }

    /// Does an `fsync` on this description have page-cache data to write back
    /// BEFORE the backend commits its own durable state?
    ///
    /// Deliberately NOT "is `fsync` legal here" — that answer belongs to
    /// [`Self::fsync`] alone, so a backend that installs a real `fsync` slot on
    /// a type the generic table calls streaming (Linux does have such
    /// character devices) keeps its own answer and cannot be overruled by a
    /// list kept elsewhere. This is only the writeback-ordering question, and
    /// the byte-addressable types are exactly the ones that can have a page
    /// cache. # C: O(1)
    fn fsync_needs_writeback(&self, file: &File) -> bool {
        crate::file::fsync_slot_present(file.inode().file_type())
    }

    /// `FMODE_CAN_ODIRECT` — does this backend have a real `a_ops->direct_IO`,
    /// i.e. an I/O path that genuinely bypasses the page cache?
    ///
    /// The bit is set from whether the backend's address-space ops install a
    /// `direct_IO` callback, and `open(2)` returns `EINVAL` for `O_DIRECT`
    /// without it. Default `false` — a backend must claim direct I/O, never
    /// inherit the claim, because the failure mode of being wrong is that a
    /// caller relying on cache bypass for correctness gets silently buffered
    /// I/O and no indication. Backends whose pages ARE the store (tmpfs/shmem)
    /// answer `true` because bypassing the cache is vacuous there. # C: O(1)
    fn can_odirect(&self, _inode: &Inode) -> bool { false }

    /// `f_op->llseek` SEEK_HOLE/SEEK_DATA core (Linux `generic_file_llseek` →
    /// `*_seek_hole_data`): map the starting byte `offset` to the next data byte
    /// (`HoleOrData::Data`) or the next hole (`HoleOrData::Hole`) and return the
    /// resulting absolute position. The generic default treats the file as fully
    /// data with a single implicit hole at EOF — correct for in-memory /
    /// non-sparse backends (tmpfs/procfs/memfd): SEEK_DATA returns `offset`
    /// unchanged, SEEK_HOLE returns `i_size`, and an `offset >= i_size` (at or
    /// past EOF, where no data and no further hole exist) is `ENXIO`. A sparse
    /// backend (ext4 with hole-punch) overrides this to walk its extent map.
    /// # C: O(1) generic; backend-dependent override
    fn seek_hole_data(&self, inode: &Inode, offset: u64, which: HoleOrData) -> KResult<u64> {
        let size = inode.size();
        // At or past EOF there is neither data nor a subsequent hole → ENXIO
        // (Linux `vfs_setpos` precondition for both whences).
        if offset >= size { return Err(VfsError::Enxio); }
        match which {
            HoleOrData::Data => Ok(offset), // non-sparse: every byte < EOF is data
            HoleOrData::Hole => Ok(size),   // the implicit hole sits at EOF
        }
    }

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
