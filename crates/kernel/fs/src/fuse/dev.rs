// `/dev/fuse` — the misc char device (major 10, minor 229) that a libfuse
// daemon `open`s to obtain a FUSE channel (`fs/fuse/dev.c` `fuse_dev_operations`).
//
// Unlike the stateless mem/misc devices, each OPEN of `/dev/fuse` is an
// INDEPENDENT channel, so the per-open [`FuseConn`] cannot live on the shared
// inode. It is created lazily on first access and keyed by the open `File`'s
// allocation identity in a side table (the exact pattern `fs::pipe` uses for a
// named FIFO's shared ring), then handed to `mount("fuse", …, "fd=N")` which
// resolves the SAME `Arc<File>` and looks the channel up by the same key.
//
//   read(/dev/fuse)  → dequeue the next kernel request (blocks if none queued)
//   write(/dev/fuse) → submit a reply, matched to its request by `unique`
//   poll(/dev/fuse)  → POLLIN when a request is queued, POLLOUT always
//   close(/dev/fuse) → abort the connection (wake every blocked VFS caller)

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use sync::{Spinlock, Tty as FuseClass};
use vfs::{File, FileOps, FileType, InodeBuilder, InodeRef, KResult, PollSubscribers, VfsError};
use vfs::{POLL_IN, POLL_OUT, mk_mode};
use vfs::devnode::Devt;

use super::conn::FuseConn;

/// `/dev/fuse` device numbers (Linux `FUSE_MINOR` under the misc major).
mod ids {
    pub(crate) const DEV_MAJOR: u32 = 10;
    pub(crate) const DEV_MINOR: u32 = 229;
    pub(crate) const DEV_INO: u64 = 0x2000_00F0;
}
pub const FUSE_DEV_MAJOR: u32 = ids::DEV_MAJOR;
pub const FUSE_DEV_MINOR: u32 = ids::DEV_MINOR;
/// Fixed inode number for the single `/dev/fuse` node (devfs pseudo-dev range).

/// `File` allocation identity → its channel. An entry exists from the open's
/// first channel access until `on_release_file` (last close) removes it. # C: O(1)
static FUSE_CONNS: Spinlock<BTreeMap<usize, Arc<FuseConn>>, FuseClass>
    = Spinlock::new(BTreeMap::new());

/// Channel key for an open `/dev/fuse` file — its `File` allocation address. The
/// daemon's read/write and the `mount` fd-resolution both reach the SAME
/// `Arc<File>` (the fd table's entry), so the key is stable and shared. # C: O(1)
fn conn_key(file: &File) -> usize { file as *const File as usize }

/// Get (or create on first access) the channel for an open `/dev/fuse` `File`.
/// The new channel adopts the inode's poll subscriber set so a request enqueue
/// wakes the daemon's `epoll`. # C: O(log N)
pub fn conn_for(file: &File) -> Arc<FuseConn> {
    let key = conn_key(file);
    let mut g = FUSE_CONNS.lock();
    if let Some(c) = g.get(&key) { return c.clone(); }
    let subs = file.inode().poll_subscribers_arc()
        .unwrap_or_else(|| Arc::new(PollSubscribers::new()));
    let c = FuseConn::new(subs);
    g.insert(key, c.clone());
    c
}

/// Look up the channel for an open `/dev/fuse` `File` WITHOUT creating one —
/// used by `mount` after it has confirmed the fd is a `/dev/fuse` file that the
/// daemon has already begun using. Returns `None` if no channel exists yet.
/// # C: O(log N)
pub fn conn_lookup(file: &File) -> Option<Arc<FuseConn>> {
    FUSE_CONNS.lock().get(&conn_key(file)).cloned()
}

/// `true` iff `file`'s data-path vtable is the `/dev/fuse` device — the check
/// `mount` makes before trusting `fd=N` (Linux `file->f_op == &fuse_dev_ops`).
/// # C: O(1)
pub fn is_fuse_dev(file: &File) -> bool { file.inode().private::<FuseDevMarker>().is_some() }

/// Zero-sized `i_private` tag marking the `/dev/fuse` inode so [`is_fuse_dev`]
/// can identify a channel fd by inode identity. # C: O(1)
struct FuseDevMarker;

/// `fuse_dev_operations` — the `/dev/fuse` `file_operations`. All methods take
/// `&File` so the per-open channel is recovered by identity. # C: channel-dependent
struct FuseDevFileOps;
impl FileOps for FuseDevFileOps {
    /// `read(/dev/fuse)` — return the next queued kernel request, blocking until
    /// one is available (Linux `fuse_dev_read`). A deliverable signal → `Eintr`;
    /// an aborted connection → `Enodev`. # C: O(msg) + park
    fn read_file(&self, file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let conn = conn_for(file);
        loop {
            match conn.dequeue(buf)? {
                0 => {}
                n => return Ok(n),
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                if sched::live::deliverable_signals_self() != 0 { return Err(VfsError::Eintr); }
                conn.park_daemon();
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(VfsError::Eagain);
        }
    }

    /// Non-blocking `read(/dev/fuse)` (`O_NONBLOCK`): `Eagain` when no request is
    /// queued rather than parking. # C: O(msg)
    fn read_nonblock_file(&self, file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let conn = conn_for(file);
        match conn.dequeue(buf)? {
            0 => Err(VfsError::Eagain),
            n => Ok(n),
        }
    }

    /// `write(/dev/fuse)` — submit a daemon reply, matched to its request by the
    /// `fuse_out_header.unique` (Linux `fuse_dev_write`). # C: O(log N)
    fn write_file(&self, file: &File, _off: u64, buf: &[u8]) -> KResult<usize> {
        conn_for(file).submit_reply(buf)
    }

    /// Non-blocking `write(/dev/fuse)` — a reply submit never blocks. # C: O(log N)
    fn write_nonblock_file(&self, file: &File, _off: u64, buf: &[u8]) -> KResult<usize> {
        conn_for(file).submit_reply(buf)
    }

    /// `poll(/dev/fuse)` — POLLIN when a request is queued (or the conn aborted),
    /// POLLOUT always (a reply can always be written). # C: O(1)
    fn poll_open_file(&self, file: &File) -> u32 {
        let conn = conn_for(file);
        let mut mask = POLL_OUT;
        if conn.has_pending() { mask |= POLL_IN; }
        mask
    }

    /// Last-close of a `/dev/fuse` channel (Linux `fuse_dev_release`): abort the
    /// connection so every blocked VFS caller wakes with `ENOTCONN`, then drop
    /// the side-table entry. Runs from `File::Drop`. # C: O(N_inflight)
    fn on_release_file(&self, file: &File) {
        if let Some(conn) = FUSE_CONNS.lock().remove(&conn_key(file)) { conn.abort(); }
    }
}

/// Build the single `/dev/fuse` inode: a char device (10:229) whose `i_fop` is
/// the channel dispatcher and whose `i_private` marks it a FUSE device. A poll
/// subscriber set is attached so an `epoll`ing daemon receives request-ready
/// edges. # C: O(1)
pub fn make_fuse_dev_inode() -> InodeRef {
    let rdev = Devt::new(FUSE_DEV_MAJOR, FUSE_DEV_MINOR).raw();
    InodeBuilder::new(ids::DEV_INO, mk_mode(FileType::CharDev, 0o666),
                      vfs::default_inode_ops(), Arc::new(FuseDevFileOps))
        .rdev(rdev)
        .poll_subs(PollSubscribers::new())
        .private(Arc::new(FuseDevMarker))
        .build()
}
