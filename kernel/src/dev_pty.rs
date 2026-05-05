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
        let (n, sigint_target) = {
            let mut g = self.pair.inner.lock();
            let n = g.master_write(buf);
            let target = if g.pending_sigint && g.foreground_pgid != 0 {
                g.pending_sigint = false;
                Some(g.foreground_pgid)
            } else { None };
            (n, target)
        };
        if let Some(pgid) = sigint_target { post_sigint_pgrp(pgid); }
        Ok(n)
    }
}

impl Inode for PtySlaveInode {
    fn ino(&self) -> Ino { self.pair.ino_slave }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        // Yield-block until at least one byte (or a complete line under
        // ICANON) is available on the master→slave queue. Matches the
        // ConsoleInode pattern; v1 has no proper waitqueue + IRQ wake.
        loop {
            let n = {
                let mut g = self.pair.inner.lock();
                if g.slave_readable() { g.slave_read(buf) } else { 0 }
            };
            if n > 0 { return Ok(n); }
            // SAFETY: process ctx; runqueue installed; preempt-off.
            unsafe { crate::sched::tick_yield(); }
        }
    }
    fn write(&self, _o: u64, buf: &[u8]) -> KResult<usize> {
        let mut g = self.pair.inner.lock();
        Ok(g.slave_write(buf))
    }
}

/// Post SIGINT (signal 2) to every task in `pgid`. Bit 1 in the
/// 64-bit sigpending mask. Returns the count posted.
/// # C: O(N_tasks)
fn post_sigint_pgrp(pgid: u32) -> usize {
    use core::sync::atomic::Ordering;
    let tasks = crate::sched::registry::tasks_in_pgrp(pgid);
    let n = tasks.len();
    for t in tasks {
        // SIGINT = 2; bit (2-1) = 1.
        t.sigpending.fetch_or(1u64 << 1, Ordering::Release);
    }
    n
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
    let master: InodeRef = Arc::new(PtyMasterInode { pair: Arc::clone(&pair) });
    let slave:  InodeRef = Arc::new(PtySlaveInode  { pair });
    let path = format!("/dev/pts/{}", n);
    crate::devfs::register_owned(path, slave);
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
    crate::devfs::register("/dev/ptmx", Arc::new(PtmxSentinelInode) as InodeRef);
}

/// Boot-time smoke for the PTY pair surface. Allocates a fresh
/// pair via `allocate_pair`, verifies the slave inode is reachable
/// in devfs at `/dev/pts/<n>`, round-trips bytes both directions,
/// and confirms the inode-number marker used by ioctl(TIOCGPTN).
/// # SAFETY: caller is the boot path; PMM up; pre-userspace.
/// # C: O(1)
pub fn smoke_test() {
    use hal::kassert;
    let (master, n) = allocate_pair();
    // Master inode must carry the 0x6000_0000 marker + low-15-bit pts_num
    // — kernel_sys_ioctl(TIOCGPTN) decodes by exactly this scheme.
    let ino = master.ino();
    kassert!((ino & 0xFFFF_8000) == 0x6000_0000, "master ino marker");
    kassert!((ino & 0x7FFF) as u32 == n, "master ino encodes pts_num");

    // Slave registered at /dev/pts/<n>.
    let mut path: alloc::string::String = alloc::string::String::with_capacity(16);
    path.push_str("/dev/pts/");
    push_dec(&mut path, n);
    let slave = crate::devfs::lookup(&path).expect("pts slave registered");
    kassert!(slave.file_type() == FileType::CharDev, "pts slave is chardev");

    // Master write → slave read (cooked: needs trailing \n; ECHO
    // also enqueues to s_to_m so master_read drains it first).
    let n1 = master.write(0, b"keys\n").expect("master write");
    kassert!(n1 == 5, "master write len (cooked echo accepts all)");
    let mut buf = [0u8; 8];
    // Drain ECHO bytes from master read first.
    let echoed = master.read(0, &mut buf).expect("master read echo");
    kassert!(echoed == 5, "echo len");
    kassert!(&buf[..5] == b"keys\n", "echo bytes");
    let r1 = slave.read(0, &mut buf).expect("slave read");
    kassert!(r1 == 5, "slave read len");
    kassert!(&buf[..5] == b"keys\n", "master→slave bytes");

    // Slave write → master read (no ldisc on this direction).
    let n2 = slave.write(0, b"output").expect("slave write");
    kassert!(n2 == 6, "slave write len");
    let r2 = master.read(0, &mut buf).expect("master read");
    kassert!(r2 == 6, "master read len");
    kassert!(&buf[..6] == b"output", "slave→master bytes");

    sigint_chain_smoke();

    debug_boot! { klog::write_raw(b"[INFO]  pty-smoke: ok\n"); }
}

/// Validates the cooked-mode → pending_sigint → foreground_pgid →
/// SIGINT-on-task chain end-to-end without a userspace blob.
/// Plants a fake task into the registry, points a fresh pair's
/// foreground_pgid at it, feeds a VINTR through the master inode,
/// then asserts SIGINT bit is set on the fake task's sigpending.
fn sigint_chain_smoke() {
    use core::sync::atomic::Ordering;
    use hal::kassert;
    use sched::{SchedClass, Task};

    let fake_tid = 0xDEAD_C001;
    let fake = alloc::sync::Arc::new(Task::new(
        fake_tid, "pty-smoke-target", SchedClass::Normal { weight: 1024 },
    ));
    fake.pgid.store(fake_tid, Ordering::Release);
    crate::sched::registry::insert(&fake);

    let (master, n) = allocate_pair();
    let pair = pair_for(n).expect("pair_for");
    pair.with_pair(|p| {
        kassert!(p.lflag() != 0, "cooked default");
        p.foreground_pgid = fake_tid;
    });

    // Master inode write of VINTR: cooked mode drops the byte,
    // sets pending_sigint, echoes "^C", then PtyMasterInode::write
    // posts SIGINT to every task in foreground_pgid.
    let n1 = master.write(0, &[tty::pty::VINTR]).expect("master write VINTR");
    kassert!(n1 == 1, "VINTR consumed");

    let pending = fake.sigpending.load(Ordering::Acquire);
    // SIGINT = 2; bit 1.
    kassert!(pending & (1u64 << 1) != 0, "SIGINT delivered to fg pgrp");

    // pending_sigint flag must have been cleared by the kernel-side write.
    pair.with_pair(|p| kassert!(!p.pending_sigint, "pending_sigint cleared"));

    debug_boot! { klog::write_raw(b"[INFO]  pty-sigint-chain: ok\n"); }
    drop(fake); // task drops; registry's Weak decays naturally

    termios_winsize_smoke();
}

/// Boot-time termios + winsize round-trip smoke. Validates that
/// the Pair carries the configured state across reads/writes
/// without going through the kernel ioctl path.
fn termios_winsize_smoke() {
    use hal::kassert;
    let (_master, n) = allocate_pair();
    let pair = pair_for(n).expect("pair_for");

    pair.with_pair(|p| {
        kassert!(p.lflag() == tty::pty::DEFAULT_LFLAG, "default cooked lflag");
        kassert!(p.iflag() == tty::pty::DEFAULT_IFLAG, "default cooked iflag");
        kassert!(p.oflag() == tty::pty::DEFAULT_OFLAG, "default cooked oflag");
        kassert!(p.vintr() == tty::pty::DEFAULT_VINTR, "default cooked vintr");
        kassert!(p.winsize == tty::pty::Winsize::default_pty(), "default 24x80");
    });

    pair.with_pair(|p| {
        p.set_winsize(tty::pty::Winsize { rows: 50, cols: 132, xpixel: 0, ypixel: 0 });
        kassert!(p.pending_sigwinch, "set_winsize on change → pending");
        kassert!(p.winsize.rows == 50 && p.winsize.cols == 132, "winsize round-trip");
        p.pending_sigwinch = false;
        p.set_winsize(tty::pty::Winsize { rows: 50, cols: 132, xpixel: 0, ypixel: 0 });
        kassert!(!p.pending_sigwinch, "no-op set must NOT fire SIGWINCH");
    });

    debug_boot! { klog::write_raw(b"[INFO]  pty-termios-winsize: ok\n"); }
}

fn push_dec(s: &mut alloc::string::String, mut n: u32) {
    if n == 0 { s.push('0'); return; }
    let mut buf = [0u8; 11]; let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; s.push(buf[i] as char); }
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
