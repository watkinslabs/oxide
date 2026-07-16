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

use crate::file::File;
use crate::inode::{Inode, no_data_op_errno, POLL_IN, POLL_OUT};
use crate::poll_subs::PollSubscribers;
use crate::types::{FileType, KResult, VfsError};

/// `SEEK_HOLE`/`SEEK_DATA` selector for [`FileOps::seek_hole_data`] (Linux
/// `lseek(2)` whence `4`/`3`). `Data` finds the next byte ≥ `offset` that is
/// part of a data extent; `Hole` finds the next hole (or the implicit hole at
/// EOF). # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HoleOrData {
    /// `SEEK_DATA` — next data byte at/after `offset`.
    Data,
    /// `SEEK_HOLE` — next hole at/after `offset`.
    Hole,
}

/// Int-valued Linux `unlocked_ioctl` queue queries whose copy_to_user remains
/// owned by the syscall ABI layer. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IoctlIntCmd {
    /// `FIONREAD` / `SIOCINQ` — readable bytes or next datagram length.
    Fionread,
    /// `SIOCOUTQ` / `TIOCOUTQ` — protocol-defined outgoing queued bytes.
    Siocoutq,
    /// `SIOCATMARK` — whether the next TCP stream byte is the urgent mark.
    Siocatmark,
}

/// Linux `file_operations->unlocked_ioctl` operations whose usercopy remains
/// in the syscall ABI layer. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileIoctlCmd {
    /// `EXT4_IOC_GETVERSION` / legacy `FS_IOC_GETVERSION`.
    GetVersion,
    /// Pre-copyin admission for `EXT4_IOC_SETVERSION`.
    SetVersionPrepare,
    /// `EXT4_IOC_SETVERSION` / legacy `FS_IOC_SETVERSION`.
    SetVersion(u32),
    /// `FS_IOC_GETFSLABEL` on filesystem-specific `f_op->unlocked_ioctl`.
    GetFsLabel,
    /// Pre-copyin admission for `FS_IOC_SETFSLABEL`; carries CAP_SYS_ADMIN.
    SetFsLabelPrepare(bool),
    /// `FS_IOC_SETFSLABEL`: exact ext4 16-byte on-disk label payload.
    SetFsLabel([u8; 16]),
    /// Pre-copyin admission for `FITRIM`; carries CAP_SYS_ADMIN.
    FitTrimPrepare(bool),
    /// `FITRIM`: filesystem trim request after ABI-layer usercopy.
    FitTrim { start: u64, len: u64, minlen: u64 },
}

/// Return payload for [`FileOps::unlocked_ioctl`]. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileIoctlReply {
    /// ioctl succeeded without a scalar payload.
    Done,
    /// ioctl returned a 32-bit scalar copied by the ABI layer.
    U32(u32),
    /// ioctl returned an ext4 label buffer including the trailing NUL byte.
    Label([u8; 17]),
}

/// `filldir`-style sink (Linux `struct dir_context.actor` / `filldir_t`): the
/// callback `getdents` installs to pack one directory entry into the user
/// buffer. `emit` returns `false` when the buffer cannot hold the entry — the
/// driving `iterate` then stops. # C: backend-dependent
pub trait DirEmit {
    /// Pack one entry `(name, ino, d_type)` whose resume cookie is `next_pos`.
    /// Return `false` (buffer full) to stop the walk. # C: O(reclen)
    fn emit(&mut self, name: &str, ino: u64, d_type: FileType, next_pos: u64) -> bool;
}

/// `struct dir_context` (Linux `include/linux/fs.h`): the readdir cursor +
/// actor threaded through [`FileOps::iterate`]. `pos` is the resume cookie the
/// backend reads to know where to start and that [`Self::emit`] advances as
/// each entry is accepted; `actor` is the buffer-packing sink. # C: O(1)
pub struct DirContext<'a> {
    /// `ctx->pos` — current readdir cursor / resume cookie. The backend reads it
    /// to skip already-emitted entries; `emit` advances it. # C: O(1)
    pub pos: u64,
    actor: &'a mut dyn DirEmit,
}

impl<'a> DirContext<'a> {
    /// Build a context resuming at cookie `pos`, packing through `actor`. # C: O(1)
    pub fn new(pos: u64, actor: &'a mut dyn DirEmit) -> Self { Self { pos, actor } }

    /// `dir_emit` — offer one entry to the actor. On accept (`true`), advance
    /// `pos` to `next_pos` (the resume cookie just past this entry) so a stop on
    /// the FOLLOWING entry leaves `pos` at the correct resume point. On reject
    /// (`false`, buffer full) leave `pos` unchanged and return `false` so the
    /// backend stops. # C: O(reclen)
    pub fn emit(&mut self, name: &str, ino: u64, d_type: FileType, next_pos: u64) -> bool {
        if self.actor.emit(name, ino, d_type, next_pos) { self.pos = next_pos; true } else { false }
    }
}

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
    fn mmap_shared_frame(&self, inode: &Inode, off: u64) -> Option<u64> {
        inode.i_mapping().and_then(|m| m.shared_frame(off))
    }

    /// Whether this file vtable implements Linux `f_op->remap_file_range`.
    /// Default false so VFS admission reports the Linux no-op errno before
    /// calling into a backend. # C: O(1)
    fn supports_remap_file_range(&self) -> bool { false }

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

/// Default stream/regular-file vectored-write engine for backends that override
/// `write_iter_file` only for selected record-oriented objects. # C: O(sum lens)
pub fn stream_write_iter_file<O: FileOps + ?Sized>(ops: &O, file: &File, off: u64,
    bufs: &[&[u8]], nonblock: bool) -> KResult<usize>
{
    let mut total = 0usize;
    for buf in bufs {
        if buf.is_empty() { continue; }
        let r = if nonblock {
            ops.write_nonblock_file(file, off + total as u64, buf)
        } else {
            ops.write_file(file, off + total as u64, buf)
        };
        match r {
            Ok(0) => break,
            Ok(n) => { total += n; if n < buf.len() { break; } }
            Err(e) if total == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(total)
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
