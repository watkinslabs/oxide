// `/dev/fuse` — misc character device used to obtain a FUSE channel.
//
// Each open is an independent channel. The registered character driver creates
// per-open [`FuseConn`] state keyed by the open `File` identity; mount fd
// resolution and I/O therefore share one channel without inode-private routing.
//
//   read(/dev/fuse)  → dequeue the next kernel request (blocks if none queued)
//   write(/dev/fuse) → submit a reply, matched to its request by `unique`
//   poll(/dev/fuse)  → POLLIN when a request is queued, POLLOUT always
//   close(/dev/fuse) → abort the connection (wake every blocked VFS caller)

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use sync::{Devices as DriverClass, Spinlock, Tty as FuseClass};
use vfs::{CharDevOps, Devt, File, FileType, InodeRef, KResult, PollSubscribers, VfsError};
use vfs::{POLL_IN, POLL_OUT};

use super::conn::FuseConn;

/// `/dev/fuse` device numbers (Linux `FUSE_MINOR` under the misc major).
mod ids {
    pub(crate) const DEV_MAJOR: u32 = 10;
    pub(crate) const DEV_MINOR: u32 = 229;
    pub(crate) const DEV_INO: u64 = 0x2000_00F0;
    pub(crate) const DEV_COUNT: u32 = 1;
    pub(crate) const DEV_PERM: u16 = 0o666;
}
pub const FUSE_DEV_MAJOR: u32 = ids::DEV_MAJOR;
pub const FUSE_DEV_MINOR: u32 = ids::DEV_MINOR;
pub const FUSE_DEV_COUNT: u32 = ids::DEV_COUNT;
pub const FUSE_DEV_PERM: u16 = ids::DEV_PERM;

/// Canonical `/dev/fuse` device identity. # C: O(1)
pub fn fuse_devt() -> Devt { Devt::new(FUSE_DEV_MAJOR, FUSE_DEV_MINOR) }

/// `File` allocation identity → its channel. An entry exists from the open's
/// first channel access until `on_release_file` (last close) removes it. # C: O(1)
static FUSE_CONNS: Spinlock<BTreeMap<usize, Arc<FuseConn>>, FuseClass>
    = Spinlock::new(BTreeMap::new());

/// The driver object installed in the character-device registry.
static FUSE_DRIVER: Spinlock<Option<Arc<dyn CharDevOps>>, DriverClass>
    = Spinlock::new(None);

fn fuse_driver() -> Arc<dyn CharDevOps> {
    let mut driver = FUSE_DRIVER.lock();
    driver.get_or_insert_with(|| Arc::new(FuseDevOps)).clone()
}

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
    let subs = Arc::new(PollSubscribers::new());
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

/// True when this open retained the registered FUSE driver. # C: O(1)
pub fn is_fuse_dev(file: &File) -> bool {
    let Some((devt, driver)) = vfs::opened_chrdev(file) else { return false };
    devt == fuse_devt() && Arc::ptr_eq(&driver, &fuse_driver())
}

/// Registered FUSE character driver. # C: channel-dependent
pub struct FuseDevOps;
impl CharDevOps for FuseDevOps {
    fn open_file(&self, _devt: Devt, file: &File) -> KResult<()> {
        let _ = conn_for(file);
        Ok(())
    }

    /// `read(/dev/fuse)` — return the next queued kernel request, blocking until
    /// one is available (Linux `fuse_dev_read`). A deliverable signal → `Eintr`;
    /// an aborted connection → `Enodev`. # C: O(msg) + park
    fn read_file(&self, _devt: Devt, file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let conn = conn_for(file);
        loop {
            match conn.dequeue(buf)? {
                0 => {}
                n => return Ok(n),
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                // A deliverable signal interrupts the channel wait before the
                // task parks again.
                if sched::live::deliverable_signals_self() != 0 {
                    return Err(VfsError::Erestartsys);
                }
                conn.park_daemon();
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(VfsError::Eagain);
        }
    }

    /// Non-blocking `read(/dev/fuse)` (`O_NONBLOCK`): `Eagain` when no request is
    /// queued rather than parking. # C: O(msg)
    fn read_nonblock_file(&self, _devt: Devt, file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let conn = conn_for(file);
        match conn.dequeue(buf)? {
            0 => Err(VfsError::Eagain),
            n => Ok(n),
        }
    }

    /// `write(/dev/fuse)` — submit a daemon reply, matched to its request by the
    /// `fuse_out_header.unique` (Linux `fuse_dev_write`). # C: O(log N)
    fn write_file(&self, _devt: Devt, file: &File, _off: u64, buf: &[u8]) -> KResult<usize> {
        conn_for(file).submit_reply(buf)
    }

    /// Non-blocking `write(/dev/fuse)` — a reply submit never blocks. # C: O(log N)
    fn write_nonblock_file(&self, _devt: Devt, file: &File, _off: u64, buf: &[u8]) -> KResult<usize> {
        conn_for(file).submit_reply(buf)
    }

    /// `poll(/dev/fuse)` — POLLIN when a request is queued (or the conn aborted),
    /// POLLOUT always (a reply can always be written). # C: O(1)
    fn poll_file(&self, _devt: Devt, file: &File) -> KResult<u32> {
        let conn = conn_for(file);
        let mut mask = POLL_OUT;
        if conn.has_pending() { mask |= POLL_IN; }
        Ok(mask)
    }

    fn poll_subscribers_file(&self, _devt: Devt, file: &File) -> Option<Arc<PollSubscribers>> {
        Some(conn_for(file).poll_subscribers())
    }

    /// Last-close of a `/dev/fuse` channel (Linux `fuse_dev_release`): abort the
    /// connection so every blocked VFS caller wakes with `ENOTCONN`, then drop
    /// the side-table entry. Runs from `File::Drop`. # C: O(N_inflight)
    fn release_file(&self, _devt: Devt, file: &File) {
        if let Some(conn) = FUSE_CONNS.lock().remove(&conn_key(file)) { conn.abort(); }
    }
}

/// Build a `/dev/fuse` node through the canonical character-device dispatcher.
/// # C: O(1)
pub fn make_fuse_dev_inode() -> InodeRef {
    vfs::make_device_node_inode(
        ids::DEV_INO,
        FileType::CharDev,
        fuse_devt(),
        ids::DEV_PERM,
        alloc::sync::Weak::new(),
    )
}

/// Register the one-minor FUSE character-device region. # C: O(R)
pub fn register_chrdev() -> KResult<()> {
    vfs::register_chrdev_region(
        FUSE_DEV_MAJOR,
        FUSE_DEV_MINOR,
        FUSE_DEV_COUNT,
        fuse_driver(),
    )
}
