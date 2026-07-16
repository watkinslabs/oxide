#![cfg(target_os = "oxide-kernel")]  // kernel-only crate (uses tty::live/sched::live)
#![no_std]
#[macro_use] extern crate kmacros;
extern crate alloc;

// /dev/ptmx + /dev/pts/<n> per `28§5`. Each open of /dev/ptmx
// allocates a fresh `tty::Pair`, registers a slave inode at
// /dev/pts/<n> in the devfs registry, and returns the master fd.
// Subsequent open of /dev/pts/<n> binds to the same pair.
//
// Locking: each pair lives behind a single Spinlock<tty::Pair>.
// v1 doesn't split per-direction locks (master and slave I/O can
// stall briefly across the pair); per-ring locks ride a follow-up
// once we measure contention.


use alloc::format;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use sync::{Spinlock, Tty as TtyClass};
use tty::Pair as TtyPair;
use tty::Sig;
use vfs::{FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, SuperBlock, VfsError};
use vfs::{FileOps, default_inode_ops, mk_mode};
use kernfs::PseudoDir;

mod smoke;
mod ids;

/// `DEVPTS_SUPER_MAGIC` (linux/magic.h) — `statfs` `f_type` for the devpts
/// instance mounted at `/dev/pts`.
pub const DEVPTS_MAGIC: u64 = 0x1cd1;
const PTY_MASTER_MODE: u16 = 0o666;
const PTY_SLAVE_MODE: u16 = 0o620;
/// devpts `st_dev`/`fsid`. Linux mounts devpts as its OWN filesystem at
/// `/dev/pts` (distinct from devtmpfs at `/dev`), so its inodes must report a
/// dev number distinct from `devfs::DEVFS_FSID` for `(dev, ino)` uniqueness
/// across the two mounts. Now realised by the first-class [`DevptsFs`]
/// `SuperBlock` (D36/D37); the per-inode `fsid` override keeps pts slave nodes
/// reporting the devpts id even before/without an SB stamp.
pub const DEVPTS_FSID: u64 = 0x0102_1994_0000_0002;

/// Spinlock-wrapped pair shared between the master and slave inodes.
pub struct LockedPair {
    inner: Spinlock<TtyPair, TtyClass>,
    ino_master: Ino,
    ino_slave:  Ino,
    /// `TIOCSPTLCK` slave lock (Linux `TTY_PTY_LOCK`). Allocated LOCKED:
    /// glibc/musl `unlockpt(master)` (= `TIOCSPTLCK` with 0) must clear it
    /// before the slave can be opened, matching `pts_unix98_lookup`'s
    /// `-EIO` on a locked slave. POSIX requires `unlockpt` pre-slave-open.
    locked: AtomicBool,
    master_exclusive: AtomicBool,
    slave_exclusive: AtomicBool,
    master_opens: AtomicU32,
    slave_opens: AtomicU32,
}

impl LockedPair {
    fn new(pts_num: u32) -> Arc<Self> {
        let ino_master = ids::PTY_MASTER_INO_BASE | pts_num as Ino;
        let ino_slave  = ids::PTY_SLAVE_INO_BASE | pts_num as Ino;
        Arc::new(Self {
            inner: Spinlock::new(TtyPair::new(pts_num)),
            ino_master, ino_slave,
            locked: AtomicBool::new(true),
            master_exclusive: AtomicBool::new(false),
            slave_exclusive: AtomicBool::new(false),
            master_opens: AtomicU32::new(0),
            slave_opens: AtomicU32::new(0),
        })
    }
    /// # C: O(1)
    pub fn pts_num(&self) -> u32 { self.inner.lock().pts_num }
    /// `TIOCGPTLCK` read-back: 1 = locked, 0 = unlocked.
    /// # C: O(1)
    pub fn is_locked(&self) -> bool { self.locked.load(Ordering::Acquire) }
    /// `TIOCSPTLCK` setter: non-zero arg locks, zero unlocks.
    /// # C: O(1)
    pub fn set_locked(&self, v: bool) { self.locked.store(v, Ordering::Release); }
    /// TIOCEXCL/TIOCNXCL setter for one pty endpoint. # C: O(1)
    pub fn set_exclusive(&self, master: bool, v: bool) {
        if master { &self.master_exclusive } else { &self.slave_exclusive }.store(v, Ordering::Release);
    }
    /// TIOCGEXCL readback for one pty endpoint. # C: O(1)
    pub fn exclusive(&self, master: bool) -> bool {
        if master { &self.master_exclusive } else { &self.slave_exclusive }.load(Ordering::Acquire)
    }
    /// Linux `tty_reopen` TTY_EXCLUSIVE admission for one pty endpoint. # C: O(1)
    pub fn open_endpoint(&self, master: bool, cap_sys_admin: bool) -> KResult<()> {
        let excl = if master { &self.master_exclusive } else { &self.slave_exclusive };
        let opens = if master { &self.master_opens } else { &self.slave_opens };
        if excl.load(Ordering::Acquire) && opens.load(Ordering::Acquire) != 0 && !cap_sys_admin {
            return Err(VfsError::Ebusy);
        }
        opens.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    /// Last-close release for one pty endpoint. # C: O(1)
    pub fn close_endpoint(&self, master: bool) {
        let opens = if master { &self.master_opens } else { &self.slave_opens };
        let prev = opens.load(Ordering::Acquire);
        if prev != 0 { opens.fetch_sub(1, Ordering::AcqRel); }
    }
}

/// Recover the backing `LockedPair` from a pty inode's `i_private`. # C: O(1)
fn pair_of(inode: &Inode) -> KResult<&LockedPair> {
    inode.private::<LockedPair>().ok_or(VfsError::Einval)
}

/// Build the master-side (`/dev/ptmx`) inode for `pair`. CharDev `0o666`,
/// rdev `0x8000|pts`, `i_private` = the shared `Arc<LockedPair>`. # C: O(1)
pub fn make_master_inode(pair: Arc<LockedPair>) -> InodeRef {
    let ino = pair.ino_master;
    let rdev = ids::PTY_MASTER_RDEV_BASE | (pair.pts_num() & 0xff) as u32;
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, PTY_MASTER_MODE), default_inode_ops(), Arc::new(PtyMasterFileOps))
        .fsid(DEVPTS_FSID).rdev(rdev)
        .private(pair as Arc<dyn core::any::Any + Send + Sync>)
        .build()
}

/// Build the slave-side (`/dev/pts/<n>`) inode for `pair`. CharDev `0o620`,
/// rdev `0x8800|pts`. # C: O(1)
pub fn make_slave_inode(pair: Arc<LockedPair>) -> InodeRef {
    let ino = pair.ino_slave;
    let rdev = ids::PTY_SLAVE_RDEV_BASE | (pair.pts_num() & 0xff) as u32;
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, PTY_SLAVE_MODE), default_inode_ops(), Arc::new(PtySlaveFileOps))
        .fsid(DEVPTS_FSID).rdev(rdev)
        .private(pair as Arc<dyn core::any::Any + Send + Sync>)
        .build()
}

/// `file_operations` for the master (`/dev/ptmx`) side of a pty pair.
struct PtyMasterFileOps;
impl FileOps for PtyMasterFileOps {
    fn on_open(&self, inode: &Inode) -> KResult<()> {
        let pair = pair_of(inode)?;
        pair.open_endpoint(true, current_has_sys_admin())
    }

    fn read(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        let pair = pair_of(inode)?;
        // Yield-block until the slave has written something. Mirrors the slave.
        loop {
            let n = {
                let mut g = pair.inner.lock();
                if g.master_readable() { g.master_read(buf) } else { 0 }
            };
            if n > 0 { return Ok(n); }
            // SAFETY: process ctx; runqueue installed; preempt-off.
            unsafe { sched::live::tick_yield(); }
        }
    }
    /// F201: O_NONBLOCK read — EAGAIN when no data, so select()+read
    /// loops (dropbear's session pump) don't spin or block forever.
    fn read_nonblock(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        let pair = pair_of(inode)?;
        let mut g = pair.inner.lock();
        if g.master_readable() { Ok(g.master_read(buf)) } else { Err(VfsError::Eagain) }
    }
    fn write(&self, inode: &Inode, _o: u64, buf: &[u8]) -> KResult<usize> {
        let pair = pair_of(inode)?;
        let (n, signals, fg) = {
            let mut g = pair.inner.lock();
            let n = g.master_write(buf);
            let mut bits = 0u64;
            if g.pending_sigint  { bits |= 1u64 << 1;  g.pending_sigint  = false; }
            if g.pending_sigquit { bits |= 1u64 << 2;  g.pending_sigquit = false; }
            if g.pending_sigtstp { bits |= 1u64 << 19; g.pending_sigtstp = false; }
            (n, bits, g.foreground_pgid)
        };
        if signals != 0 && fg != 0 { post_signal_pgrp(fg, signals); }
        Ok(n)
    }
    /// F201: readiness for select/poll. POLLIN when slave→master
    /// queue has bytes; POLLOUT always (we don't backpressure on
    /// master writes today).
    fn poll(&self, inode: &Inode) -> u32 {
        let pair = match pair_of(inode) { Ok(p) => p, Err(_) => return vfs::POLL_ERR };
        let g = pair.inner.lock();
        let mut mask = vfs::POLL_OUT;
        if g.master_readable() { mask |= vfs::POLL_IN; }
        mask
    }
    /// B5e: last-close of the MASTER side hangs up the slave — the
    /// terminal emulator / ssh / script exiting closes its master fd,
    /// after which slave read → EOF (0) and slave write → EIO (Linux
    /// pty semantics). A slave reader parked in the yield-loop re-checks
    /// `slave_readable()` each tick, which `master_hangup` flips true via
    /// `hung_up`, so it wakes and sees EOF without an explicit nudge.
    /// # C: O(1)
    fn on_release(&self, inode: &Inode) {
        let pair = match pair_of(inode) { Ok(p) => p, Err(_) => return };
        pair.close_endpoint(true);
        let fg = {
            let mut g = pair.inner.lock();
            g.master_hangup();
            g.foreground_pgid
        };
        // Master last-close = carrier loss. Linux `__tty_hangup` delivers
        // SIGHUP + SIGCONT to the slave's foreground process group (SIGCONT
        // so a stopped job wakes to take the SIGHUP). `pending_sighup` had
        // been set but never drained — the slave's shell never saw SIGHUP.
        if fg != 0 {
            let bits = sched::Signum::Sighup.bit() | sched::Signum::Sigcont.bit();
            post_signal_pgrp(fg, bits);
        }
    }
}

/// `file_operations` for the slave (`/dev/pts/<n>`) side of a pty pair.
struct PtySlaveFileOps;
impl FileOps for PtySlaveFileOps {
    /// Linux `pts_unix98_lookup`: a `TIOCSPTLCK`-locked slave can't be
    /// opened (`-EIO`) — the master must `unlockpt` first.
    /// # C: O(1)
    fn on_open(&self, inode: &Inode) -> KResult<()> {
        let pair = pair_of(inode)?;
        if pair.is_locked() { return Err(VfsError::Eio); }
        pair.open_endpoint(false, current_has_sys_admin())
    }

    fn on_release(&self, inode: &Inode) {
        if let Ok(pair) = pair_of(inode) { pair.close_endpoint(false); }
    }
    fn read(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        let pair = pair_of(inode)?;
        // Yield-block until at least one byte (or a complete line under
        // ICANON) is available on the master→slave queue. Matches the
        // ConsoleInode pattern; v1 has no proper waitqueue + IRQ wake.
        loop {
            let n = {
                let mut g = pair.inner.lock();
                if g.slave_readable() { g.slave_read(buf) } else { 0 }
            };
            if n > 0 { return Ok(n); }
            // SAFETY: process ctx; runqueue installed; preempt-off.
            unsafe { sched::live::tick_yield(); }
        }
    }
    /// F201: O_NONBLOCK read — EAGAIN when master→slave queue empty.
    fn read_nonblock(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        let pair = pair_of(inode)?;
        let mut g = pair.inner.lock();
        if g.slave_readable() { Ok(g.slave_read(buf)) } else { Err(VfsError::Eagain) }
    }
    fn write(&self, inode: &Inode, _o: u64, buf: &[u8]) -> KResult<usize> {
        let pair = pair_of(inode)?;
        let mut g = pair.inner.lock();
        // Master hung up → slave writes fail with EIO (Linux pty semantics).
        if g.slave_hung_up() { return Err(VfsError::Eio); }
        Ok(g.slave_write(buf))
    }
    /// F201: readiness for select/poll. POLLIN when master→slave
    /// queue has bytes; POLLOUT always (slave→master is bounded by
    /// pty buffer but we don't surface backpressure yet).
    fn poll(&self, inode: &Inode) -> u32 {
        let pair = match pair_of(inode) { Ok(p) => p, Err(_) => return vfs::POLL_ERR };
        let g = pair.inner.lock();
        let mut mask = vfs::POLL_OUT;
        if g.slave_readable() { mask |= vfs::POLL_IN; }
        mask
    }
}

/// Post the bitmap of signal bits to every task in `pgid`. Bits
/// follow Linux convention (bit (sig-1) for signal `sig`). Used by
/// the master-side cooked-mode dispatch for SIGINT (^C) / SIGQUIT
/// (^\\) / SIGTSTP (^Z). Returns the count posted.
/// # C: O(N_tasks)
fn post_signal_pgrp(pgid: u32, bits: u64) -> usize {
    use core::sync::atomic::Ordering;
    let tasks = sched::live::registry::tasks_in_pgrp(pgid);
    let n = tasks.len();
    for t in tasks {
        t.sigpending.fetch_or(bits, Ordering::Release);
    }
    n
}

fn current_has_sys_admin() -> bool {
    sched::current().map(|t| t.has_cap(sched::cap::SYS_ADMIN)).unwrap_or(false)
}

static NEXT_PTS: AtomicU32 = AtomicU32::new(0);

/// pts_num → LockedPair lookup so ioctl handlers (TIOCSPGRP /
/// TIOCGPGRP) can reach the pair's foreground_pgid slot from a fd
/// without an Any-downcast on the Inode trait. Indexed by pts_num
/// (kept small + dense by NEXT_PTS).
static PAIRS: sync::Spinlock<alloc::vec::Vec<Arc<LockedPair>>, sync::TaskList>
    = sync::Spinlock::new(alloc::vec::Vec::new());

/// Resolve a pts_num to its locked pair. Used by ioctl handlers.
/// # C: O(1)
pub fn pair_for(pts_num: u32) -> Option<Arc<LockedPair>> {
    let g = PAIRS.lock();
    g.get(pts_num as usize).cloned()
}

/// Allocate a fresh PTY pair. Registers a slave inode at
/// `/dev/pts/<n>` and returns the master inode + pts number.
/// Called from sys_open's special-case for `/dev/ptmx`.
/// # SAFETY: caller is the syscall path on this CPU; devfs::register
/// holds its own lock so this is sound from any task context.
/// # C: O(N_devfs_entries)
pub fn allocate_pair() -> (InodeRef, u32) {
    let n = NEXT_PTS.fetch_add(1, Ordering::Relaxed);
    let pair = LockedPair::new(n);
    // Linux pty default: ICANON | ECHO | ISIG. tty::Pair::new starts
    // raw; flip to cooked here so userspace sees the expected default.
    pair.with_pair(|p| p.termios = tty::pty::default_termios());
    {
        let mut g = PAIRS.lock();
        if g.len() <= n as usize { g.resize_with(n as usize + 1, || Arc::clone(&pair)); }
        else { g[n as usize] = Arc::clone(&pair); }
    }
    let master = make_master_inode(Arc::clone(&pair));
    let slave  = make_slave_inode(pair);
    // Mirror the slave into BOTH: (a) the devfs registry at `/dev/pts/<n>`
    // (the legacy fallback the boot /dev/pts setup still resolves through when
    // no real devpts is mounted), and (b) THIS instance's first-class devpts
    // root under the mount-relative name `<n>` (so a `mount -t devpts` at
    // /dev/pts resolves the same slave through its own SuperBlock). D36/D37.
    devfs::register_owned(format!("/dev/pts/{}", n), Arc::clone(&slave));
    devpts_fs().root.insert_path(&format!("{}", n), slave);
    (master, n)
}

impl LockedPair {
    /// Run `f` against the locked pair. Used by ioctl handlers
    /// reaching foreground_pgid without an Any-downcast.
    /// # C: O(closure)
    pub fn with_pair<R>(&self, f: impl FnOnce(&mut tty::Pair) -> R) -> R {
        let mut g = self.inner.lock();
        f(&mut *g)
    }
}

/// Boot-time registration: register `/dev/ptmx` (sentinel inode —
/// the real factory work happens in sys_open) and the `/dev/pts`
/// directory inode so getdents64 enumerates allocated slaves.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(1)
pub fn init() {
    devfs::register("/dev/ptmx", make_ptmx_sentinel_inode());
    devfs::register_dir("/dev/pts");
}

/// Boot-time smoke for the PTY pair surface. Allocates a fresh
/// pair via `allocate_pair`, verifies the slave inode is reachable
/// in devfs at `/dev/pts/<n>`, round-trips bytes both directions,
/// and confirms the inode-number marker used by ioctl(TIOCGPTN).
/// # SAFETY: caller is the boot path; PMM up; pre-userspace.
/// # C: O(1)
pub fn smoke_test() {
    smoke::smoke_test();
}

/// `file_operations` for the `/dev/ptmx` sentinel — read/write return EIO
/// (the real factory work is the open-path special-case → `allocate_pair`).
struct PtmxSentinelFileOps;
impl FileOps for PtmxSentinelFileOps {
    fn read(&self, _i: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Eio) }
    fn write(&self, _i: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// Sentinel inode for `/dev/ptmx`. Its only role is to surface a
/// CharDev type at lookup-time — the open path detects this exact
/// path and routes to `allocate_pair`. read/write on the sentinel
/// itself return EIO (caller used the wrong fd). Stays on
/// `devfs::DEVFS_FSID`: the `/dev/ptmx` directory entry lives in
/// devtmpfs (`/dev`), only the allocated master/slave pair inodes are
/// on the devpts fs (`DEVPTS_FSID`). # C: O(1)
pub fn make_ptmx_sentinel_inode() -> InodeRef {
    InodeBuilder::new(ids::PTMX_ROOT_INO, mk_mode(FileType::CharDev, PTY_MASTER_MODE), default_inode_ops(), Arc::new(PtmxSentinelFileOps))
        .fsid(devfs::DEVFS_FSID).rdev(ids::PTMX_RDEV)
        .build()
}

/// The per-instance `ptmx` node Linux materialises INSIDE the devpts mount at
/// `/dev/pts/ptmx` (D37 — ptmx-inside-pts). Stamped with `DEVPTS_FSID` (it
/// belongs to the devpts fs, unlike the `/dev/ptmx` directory entry which lives
/// in devtmpfs). The working pty factory stays the `/dev/ptmx` open-path
/// special-case (preserving current semantics, `28§5`); this node exists so the
/// devpts root is structurally complete (it stats/lists as a 0o666 chardev).
/// # C: O(1)
fn make_pts_ptmx_inode() -> InodeRef {
    InodeBuilder::new(ids::PTMX_MOUNT_INO, mk_mode(FileType::CharDev, PTY_MASTER_MODE), default_inode_ops(), Arc::new(PtmxSentinelFileOps))
        .fsid(DEVPTS_FSID).rdev(ids::PTMX_RDEV)
        .build()
}

// ---------------------------------------------------------------------------
// DevptsFs — first-class devpts filesystem (D36/D37).
//
// Linux mounts devpts as its OWN filesystem at `/dev/pts` with its own
// `super_block` (DEVPTS_SUPER_MAGIC) whose root directory holds `ptmx` plus the
// per-pty slave nodes `/dev/pts/<n>`. This backend gives oxide that
// first-class object: a singleton `DevptsFs` (matching the current single
// global pty namespace — `NEXT_PTS`/`PAIRS` are global; multi-instance pts
// namespaces are a noted residual) whose `kernfs::PseudoDir` root exposes the
// ptmx node + slaves from THIS fs's root rather than the devfs path registry.
// `mount -t devpts` / `fsopen("devpts")` materialise the real SB via the
// fsmount_common registry. The devfs registry mirror is kept as a fallback so
// the boot /dev/pts setup is non-fatal even when no devpts is mounted.
// ---------------------------------------------------------------------------

/// A first-class devpts filesystem instance: its own `kernfs::PseudoDir` root
/// holding `ptmx` + the per-pty slave nodes, surfaced under `DEVPTS_MAGIC` /
/// `DEVPTS_FSID` once the mount engine builds its `SuperBlock`.
pub struct DevptsFs {
    root: Arc<PseudoDir>,
}

impl DevptsFs {
    /// Build a fresh instance: an empty `PseudoDir` root seeded with the
    /// per-instance `ptmx` node. Slaves are inserted lazily by
    /// [`allocate_pair`]. # C: O(1)
    fn new() -> Arc<Self> {
        let root = PseudoDir::new_root(kernfs::dir_ino("/dev/pts"), DEVPTS_FSID);
        root.insert_path("ptmx", make_pts_ptmx_inode());
        Arc::new(Self { root })
    }

    /// The instance root directory (tree-population entry point). # C: O(1)
    pub fn root_dir(&self) -> &Arc<PseudoDir> { &self.root }
}

impl vfs::fs::FileSystem for DevptsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "devpts" }
    /// `DEVPTS_SUPER_MAGIC` — `statfs`/`fstatfs` `f_type`. # C: O(1)
    fn magic(&self) -> u64 { DEVPTS_MAGIC }
    /// Non-`None` directory root: the path walk crosses into the mount and the
    /// post-mount verify accepts it. # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(self.root.as_inode()) }
    /// Back-stamp the SB (`fill_super`) so the root dir's inodes report the
    /// instance `s_dev`. The slave nodes carry an explicit `DEVPTS_FSID`
    /// override (set at build), so their `st_dev` is the devpts fs id either
    /// way. # C: O(tree)
    fn set_sb(&self, sb: Weak<SuperBlock>) -> vfs::KResult<()> { self.root.set_sb(sb); Ok(()) }
}

/// Process-wide singleton devpts instance. The current pty namespace is global
/// (`NEXT_PTS`/`PAIRS`), so one `DevptsFs` backs every devpts mount; this keeps
/// the SB's slave set identical to the global pair table. # C: O(1) after first.
static DEVPTS_FS: Spinlock<Option<Arc<DevptsFs>>, sync::TaskList> = Spinlock::new(None);

/// The singleton [`DevptsFs`] (lazily created). The fsmount_common registry
/// constructor and [`allocate_pair`]'s slave mirror both resolve through this,
/// so a mounted devpts SB and the devfs fallback observe the same slaves.
/// # C: O(1)
pub fn devpts_fs() -> Arc<DevptsFs> {
    let mut g = DEVPTS_FS.lock();
    if let Some(fs) = g.as_ref() { return Arc::clone(fs); }
    let fs = DevptsFs::new();
    *g = Some(Arc::clone(&fs));
    fs
}
