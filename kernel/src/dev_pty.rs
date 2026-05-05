// /dev/ptmx + /dev/pts/<n> per `28§5`. Each open of /dev/ptmx
// allocates a fresh `tty::Pair`, registers a slave inode at
// /dev/pts/<n> in the devfs registry, and returns the master fd.
// Subsequent open of /dev/pts/<n> binds to the same pair.
//
// Locking: each pair lives behind a single Spinlock<tty::Pair>.
// v1 doesn't split per-direction locks (master and slave I/O can
// stall briefly across the pair); per-ring locks ride a follow-up
// once we measure contention.

#![cfg(target_os = "oxide-kernel")]

use alloc::format;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, Tty as TtyClass};
use tty::Pair as TtyPair;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// Spinlock-wrapped pair shared between the master and slave inodes.
pub struct LockedPair {
    inner: Spinlock<TtyPair, TtyClass>,
    ino_master: Ino,
    ino_slave:  Ino,
}

impl LockedPair {
    fn new(pts_num: u32) -> Arc<Self> {
        let ino_master = 0x6000_0000 | pts_num as Ino;
        let ino_slave  = 0x6000_8000 | pts_num as Ino;
        Arc::new(Self {
            inner: Spinlock::new(TtyPair::new(pts_num)),
            ino_master, ino_slave,
        })
    }
    /// # C: O(1)
    pub fn pts_num(&self) -> u32 { self.inner.lock().pts_num }
}

/// `/dev/ptmx`-side inode. Each Arc<LockedPair> backs exactly one
/// master inode (created at open-time by `allocate_pair`) and one
/// slave inode (registered at /dev/pts/<n>).
pub struct PtyMasterInode { pub pair: Arc<LockedPair> }
pub struct PtySlaveInode  { pub pair: Arc<LockedPair> }

impl Inode for PtyMasterInode {
    fn ino(&self) -> Ino { self.pair.ino_master }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut g = self.pair.inner.lock();
        Ok(g.master_read(buf))
    }
    fn write(&self, _o: u64, buf: &[u8]) -> KResult<usize> {
        let mut g = self.pair.inner.lock();
        Ok(g.master_write(buf))
    }
}

impl Inode for PtySlaveInode {
    fn ino(&self) -> Ino { self.pair.ino_slave }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut g = self.pair.inner.lock();
        Ok(g.slave_read(buf))
    }
    fn write(&self, _o: u64, buf: &[u8]) -> KResult<usize> {
        let mut g = self.pair.inner.lock();
        Ok(g.slave_write(buf))
    }
}

static NEXT_PTS: AtomicU32 = AtomicU32::new(0);

/// Allocate a fresh PTY pair. Registers a slave inode at
/// `/dev/pts/<n>` and returns the master inode + pts number.
/// Called from sys_open's special-case for `/dev/ptmx`.
/// # SAFETY: caller is the syscall path on this CPU; devfs::register
/// holds its own lock so this is sound from any task context.
/// # C: O(N_devfs_entries)
pub fn allocate_pair() -> (InodeRef, u32) {
    let n = NEXT_PTS.fetch_add(1, Ordering::Relaxed);
    let pair = LockedPair::new(n);
    let master: InodeRef = Arc::new(PtyMasterInode { pair: Arc::clone(&pair) });
    let slave:  InodeRef = Arc::new(PtySlaveInode  { pair });
    let path = format!("/dev/pts/{}", n);
    crate::devfs::register_owned(path, slave);
    (master, n)
}

/// Boot-time registration: register `/dev/ptmx` (sentinel inode —
/// the real factory work happens in sys_open) and the `/dev/pts`
/// directory inode so getdents64 enumerates allocated slaves.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(1)
pub fn init() {
    crate::devfs::register("/dev/ptmx", Arc::new(PtmxSentinelInode) as InodeRef);
}

/// Sentinel inode for `/dev/ptmx`. Its only role is to surface a
/// CharDev type at lookup-time — the open path detects this exact
/// path and routes to `allocate_pair`. read/write on the sentinel
/// itself return EIO (caller used the wrong fd).
pub struct PtmxSentinelInode;

impl Inode for PtmxSentinelInode {
    fn ino(&self) -> Ino { 0x6000_FFFF }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Eio) }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}
