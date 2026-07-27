// `file_operations` for the two halves of a pty pair (`28§5`).
//
// Slave (`/dev/pts/<n>`) read/write run the job-control gate first, exactly
// where Linux does: n_tty's `job_control` at the top of `n_tty_read`
// (`drivers/tty/n_tty.c:2200`, before the O_NONBLOCK branch at `:2207`) and
// `tty_check_change` at the top of `n_tty_write` (`drivers/tty/n_tty.c`).
// Master (`/dev/ptmx`) is nobody's controlling terminal
// (`drivers/tty/tty_io.c:2166-2167`), so it is never gated.

use core::sync::atomic::Ordering;

use vfs::{FileOps, Inode, Ino, KResult, VfsError};

use crate::{pair_of, LockedPair};

/// Linux `job_control`/`tty_check_change` for the slave half. Snapshots the
/// pair's job-control state and releases the pair lock BEFORE the check: the
/// orphan scan walks the task registry and allocates.
/// # C: O(pgrp size)
fn slave_jobctl(pair: &LockedPair, ino: Ino, access: tty::jobctl::Access) -> KResult<()> {
    let (fg, sid, lflag) = pair.with_pair(|p| (p.foreground_pgid, p.session_pid, p.lflag()));
    tty::jobctl::check(fg, sid, ino, lflag, access)
}

/// `file_operations` for the master (`/dev/ptmx`) side of a pty pair.
pub(crate) struct PtyMasterFileOps;
impl FileOps for PtyMasterFileOps {
    fn on_open(&self, inode: &Inode) -> KResult<()> {
        let pair = pair_of(inode)?;
        pair.open_endpoint(true, crate::current_has_sys_admin())
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
            if g.pending_sigint  { bits |= sched::Signum::Sigint.bit();  g.pending_sigint  = false; }
            if g.pending_sigquit { bits |= sched::Signum::Sigquit.bit(); g.pending_sigquit = false; }
            if g.pending_sigtstp { bits |= sched::Signum::Sigtstp.bit(); g.pending_sigtstp = false; }
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
pub(crate) struct PtySlaveFileOps;
impl FileOps for PtySlaveFileOps {
    /// Linux `pts_unix98_lookup`: a `TIOCSPTLCK`-locked slave can't be
    /// opened (`-EIO`) — the master must `unlockpt` first.
    /// # C: O(1)
    fn on_open(&self, inode: &Inode) -> KResult<()> {
        let pair = pair_of(inode)?;
        if pair.is_locked() { return Err(VfsError::Eio); }
        pair.open_endpoint(false, crate::current_has_sys_admin())
    }

    fn on_release(&self, inode: &Inode) {
        if let Ok(pair) = pair_of(inode) { pair.close_endpoint(false); }
    }
    fn read(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        let pair = pair_of(inode)?;
        slave_jobctl(pair, inode.ino(), tty::jobctl::Access::Read)?;
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
        // `n_tty_read` runs `job_control` at `:2200`, BEFORE the O_NONBLOCK
        // trylock at `:2207` — a background job gets SIGTTIN, not EAGAIN.
        slave_jobctl(pair, inode.ino(), tty::jobctl::Access::Read)?;
        let mut g = pair.inner.lock();
        if g.slave_readable() { Ok(g.slave_read(buf)) } else { Err(VfsError::Eagain) }
    }
    fn write(&self, inode: &Inode, _o: u64, buf: &[u8]) -> KResult<usize> {
        let pair = pair_of(inode)?;
        slave_jobctl(pair, inode.ino(), tty::jobctl::Access::Write)?;
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
pub(crate) fn post_signal_pgrp(pgid: u32, bits: u64) -> usize {
    let tasks = sched::live::registry::tasks_in_pgrp(pgid);
    let n = tasks.len();
    for t in tasks {
        t.sigpending.fetch_or(bits, Ordering::Release);
        sched::live::signal_wake_up(&t);
    }
    n
}
