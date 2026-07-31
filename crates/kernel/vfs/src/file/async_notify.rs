// fasync / `O_ASYNC` SIGIO delivery (Linux `fs/fcntl.c` `kill_fasync` ->
// `send_sigio` -> `send_sigio_to_task`).
//
// The registration list is owned by the SOURCE's poll queue
// (`Inode::poll_subscribers`), exactly as Linux hangs `pipe->fasync_readers`
// off the pipe's wait queue and `socket_wq->fasync_list` off the socket's. That
// is what makes every existing readiness site drive SIGIO without a second
// registry to keep in sync: whatever wakes a poller wakes the fasync holders.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU64, Ordering};

use crate::inode::InodeRef;

use super::File;

/// SIGIO delivery hook (Linux `send_sigio`/`kill_pid_info`): installed at boot
/// by the sched signal module so the VFS fasync path can post a signal to a
/// pid/pgrp without `vfs` depending on `sched`. `0` = not installed (host
/// tests, early boot). # C: O(1)
pub(crate) static SIGIO_HOOK: AtomicU64 = AtomicU64::new(0);

/// `f_owner_ex.type` / Linux `enum pid_type` as `F_SETOWN_EX` names it
/// (`include/uapi/asm-generic/fcntl.h`). The ONE owner of these values.
pub mod owner_type {
    /// `F_OWNER_TID` — Linux `PIDTYPE_PID`: one thread.
    pub const F_OWNER_TID:  i32 = 0;
    /// `F_OWNER_PID` — Linux `PIDTYPE_TGID`: every thread of one process.
    pub const F_OWNER_PID:  i32 = 1;
    /// `F_OWNER_PGRP` — Linux `PIDTYPE_PGID`: every process in a group.
    pub const F_OWNER_PGRP: i32 = 2;
}

/// One async-I/O readiness notification, as `send_sigio_to_task` consumes it.
/// POD so the hook can cross the vfs→sched boundary as a plain `fn` pointer.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct AsyncSignal {
    /// `f_owner.pid` — the recorded id, always non-negative for a live owner
    /// (`0` = no target). A process group is named by `ty`, not by a sign.
    pub owner: i32,
    /// `f_owner.pid_type` — see [`owner_type`]. Decides whether the signal goes
    /// to one thread, one process, or a whole process group.
    pub ty: i32,
    /// The signal actually delivered: the `F_SETSIG` value, else `SIGIO`/`SIGURG`.
    pub sig: i32,
    /// `fown->uid` — the `F_SETOWN`-time real uid, for `sigio_perm`.
    pub uid: u32,
    /// `fown->euid` — the `F_SETOWN`-time effective uid, for `sigio_perm`.
    pub euid: u32,
    /// `si_code` — the `POLL_*` reason, or `SI_SIGIO` when the chosen signal
    /// already owns signal-specific si_codes (`sig_specific_sicodes`).
    pub code: i32,
    /// `si_band` — `band_table[reason - POLL_IN]`.
    pub band: i64,
    /// `si_fd` — the descriptor recorded when `O_ASYNC` was enabled.
    pub fd: i32,
    /// `F_SETSIG` chose a signal, so the `_sigpoll` record is meaningful.
    /// `false` is Linux's `case 0:` arm — plain `SIGIO` with `SEND_SIG_PRIV`
    /// and no queued record, which is also the fallback when queuing fails.
    pub queued: bool,
}

/// Install the SIGIO delivery hook used by fasync (`O_ASYNC`). Called once at
/// kernel init by the sched signal module. # C: O(1)
pub fn set_sigio_hook(f: fn(AsyncSignal)) {
    SIGIO_HOOK.store(f as u64, Ordering::Release);
}

/// `POLL_*` si_codes an async-I/O signal carries (`asm-generic/siginfo.h`).
/// Also the index base into [`band_for`]'s table.
pub mod reason {
    /// Data input available.
    pub const POLL_IN:  i32 = 1;
    /// Output buffers available.
    pub const POLL_OUT: i32 = 2;
    /// Input message available.
    pub const POLL_MSG: i32 = 3;
    /// I/O error.
    pub const POLL_ERR: i32 = 4;
    /// High-priority (out-of-band) input available.
    pub const POLL_PRI: i32 = 5;
    /// Device disconnected.
    pub const POLL_HUP: i32 = 6;
    /// `NSIGPOLL` — the number of defined reasons.
    pub const NSIGPOLL: i32 = 6;
}

/// Linux `band_table[NSIGPOLL]` (`fs/fcntl.c`): the poll mask reported as
/// `si_band` for each `POLL_*` reason. Out-of-range reasons report `~0`, which
/// is what Linux's `reason - POLL_IN >= NSIGPOLL` arm does.
///
/// `mangle_poll` is the identity on x86_64 and aarch64 (neither overrides the
/// asm-generic `POLL*` values), so the `EPOLL*` bits pass through unchanged.
/// # C: O(1)
pub fn band_for(reason: i32) -> i64 {
    use crate::inode::{POLL_ERR, POLL_HUP, POLL_IN, POLL_MSG, POLL_OUT, POLL_PRI,
                       POLL_RDBAND, POLL_RDNORM, POLL_WRBAND, POLL_WRNORM};
    let m: u32 = match reason {
        reason::POLL_IN  => POLL_IN | POLL_RDNORM,
        reason::POLL_OUT => POLL_OUT | POLL_WRNORM | POLL_WRBAND,
        reason::POLL_MSG => POLL_IN | POLL_RDNORM | POLL_MSG,
        reason::POLL_ERR => POLL_ERR,
        reason::POLL_PRI => POLL_PRI | POLL_RDBAND,
        reason::POLL_HUP => POLL_HUP | POLL_ERR,
        _ => return !0,
    };
    m as i64
}

/// Classify a readiness mask into the single `POLL_*` reason Linux's event
/// sites name by hand. Error and hangup outrank data, and out-of-band data
/// outranks ordinary data — the same precedence `sk_wake_async`'s call sites
/// use (`POLL_ERR` from `sk_error_report`, `POLL_HUP` on FIN, `POLL_PRI` for
/// urgent data, then `POLL_IN`/`POLL_OUT`).
///
/// `None` when the mask names no reason, so a wake for an event nobody can
/// receive a signal about sends none.
/// # C: O(1)
pub fn reason_for_mask(mask: u32) -> Option<i32> {
    use crate::inode::{POLL_ERR, POLL_HUP, POLL_IN, POLL_OUT, POLL_PRI, POLL_RDNORM, POLL_WRNORM};
    if mask & POLL_ERR != 0 { return Some(reason::POLL_ERR); }
    if mask & POLL_HUP != 0 { return Some(reason::POLL_HUP); }
    if mask & POLL_PRI != 0 { return Some(reason::POLL_PRI); }
    if mask & (POLL_IN | POLL_RDNORM) != 0 { return Some(reason::POLL_IN); }
    if mask & (POLL_OUT | POLL_WRNORM) != 0 { return Some(reason::POLL_OUT); }
    None
}

/// Linux `SIG_SPECIFIC_SICODES_MASK` (`include/linux/signal.h`): signals that
/// already define their own si_codes, so a `POLL_*` code would be ambiguous.
/// `send_sigio_to_task` substitutes `SI_SIGIO` for those — except `SIGPOLL`
/// itself (== `SIGIO`), whose si_codes ARE the `POLL_*` set.
/// # C: O(1)
pub fn sicode_for(sig: i32, reason: i32) -> i32 {
    /// `SI_SIGIO` (`asm-generic/siginfo.h`) — sent by queued SIGIO.
    const SI_SIGIO: i32 = -5;
    const SIGILL: i32 = 4;  const SIGTRAP: i32 = 5;  const SIGFPE: i32 = 8;
    const SIGBUS: i32 = 7;  const SIGSEGV: i32 = 11; const SIGCHLD: i32 = 17;
    const SIGPOLL: i32 = 29; const SIGSYS: i32 = 31;
    if sig == SIGPOLL { return reason; }
    match sig {
        SIGILL | SIGFPE | SIGSEGV | SIGBUS | SIGTRAP | SIGCHLD | SIGSYS => SI_SIGIO,
        _ => reason,
    }
}

/// Register an open file description for fasync SIGIO delivery (Linux
/// `fasync_helper(.., on=1)` linking a `fasync_struct` onto the source's list).
/// Idempotent. `false` when the inode has no poll source — such a backend can
/// never signal readiness, which is why Linux gives it no `f_op->fasync`
/// either. # C: O(N) registered fds
pub fn fasync_register(file: &Arc<File>) -> bool {
    match file.inode().poll_subscribers() {
        Some(s) => { s.fasync_add(file); true }
        None => false,
    }
}

/// Unregister an open file description from fasync delivery (Linux
/// `fasync_helper(.., on=0)`). Called when `O_ASYNC` is turned off via
/// `F_SETFL` and from `File::drop`. # C: O(N) registered fds
pub fn fasync_unregister(file: &File) {
    if let Some(s) = file.inode().poll_subscribers() { s.fasync_del(file); }
}

/// Count of live fasync registrations on `inode` (prunes dead entries).
/// Test/observability accessor. # C: O(N) registered fds
pub fn fasync_registered(inode: &InodeRef) -> usize {
    inode.poll_subscribers().map(|s| s.fasync_len()).unwrap_or(0)
}

/// `kill_fasync(&inode->i_fasync, sig, band)` (Linux `fs/fcntl.c`): deliver the
/// async-ready signal to every `O_ASYNC` fd open on `inode`. `reason` is the
/// `POLL_*` code naming what became ready; `sig` is `SIGIO` for ordinary
/// readiness and `SIGURG` for out-of-band data.
/// # C: O(N) registered fds
pub fn kill_fasync(inode: &InodeRef, sig: i32, reason: i32) {
    if let Some(s) = inode.poll_subscribers() { s.kill_fasync(sig, reason); }
}

impl File {
    /// `F_SETOWN` (Linux `f_setown` -> `__f_setown` -> `f_modown`): set the
    /// SIGIO/SIGURG delivery target (`>0` a task, `<0` a `-pgrp`, `0` clears)
    /// AND snapshot the requesting credentials for the later `sigio_perm`
    /// check. Stores the bare id in `owner` (what `F_GETOWN` returns) and the
    /// packed (uid, euid) in `owner_creds`.
    ///
    /// The two ids are taken SEPARATELY — `fown->uid = current_uid()` and
    /// `fown->euid = current_euid()` — because `sigio_perm` treats them
    /// differently: only the effective id grants the root bypass. Packing the
    /// real uid into both slots, which is what this did before, silently handed
    /// that bypass to any process whose real uid was 0.
    /// # C: O(1)
    pub fn f_setown(&self, id: i32, ty: i32, uid: u32, euid: u32) {
        self.owner.store(id, Ordering::Release);
        self.owner_type.store(ty, Ordering::Release);
        self.owner_creds.store(((uid as u64) << 32) | euid as u64, Ordering::Release);
    }

    /// `F_GETOWN` (Linux `f_getown`): the delivery target id, with a process
    /// group reported as a NEGATIVE pgid — the legacy `F_GETOWN` encoding that
    /// predates `F_GETOWN_EX`. # C: O(1)
    pub fn f_getown(&self) -> i32 {
        let id = self.owner.load(Ordering::Acquire);
        if self.owner_type.load(Ordering::Acquire) == owner_type::F_OWNER_PGRP { -id } else { id }
    }

    /// `f_owner.pid_type` — which kind of id `f_owner` names. # C: O(1)
    pub fn f_owner_type(&self) -> i32 { self.owner_type.load(Ordering::Acquire) }

    /// `f_owner` credential snapshot `(uid, euid)` from the last `F_SETOWN`
    /// (Linux `struct fown_struct.uid/.euid`). # C: O(1)
    pub fn f_owner_creds(&self) -> (u32, u32) {
        let v = self.owner_creds.load(Ordering::Acquire);
        ((v >> 32) as u32, v as u32)
    }

    /// `F_SETSIG` (Linux): choose the signal delivered on async-I/O readiness;
    /// `0` restores the default (SIGIO for data, SIGURG for OOB). # C: O(1)
    pub fn set_sig(&self, sig: i32) { self.f_sig.store(sig, Ordering::Release); }

    /// `F_GETSIG` (Linux). # C: O(1)
    pub fn sig(&self) -> i32 { self.f_sig.load(Ordering::Acquire) }

    /// `fasync_struct.fa_fd` — the descriptor number `O_ASYNC` was enabled on,
    /// reported to the handler as `si_fd`. `-1` until a backend `f_op->fasync`
    /// records one. # C: O(1)
    pub fn fasync_fd(&self) -> i32 { self.fa_fd.load(Ordering::Acquire) }

    /// Record `fa_fd` (Linux `fasync_insert_entry`'s `new->fa_fd = fd`).
    /// # C: O(1)
    pub fn set_fasync_fd(&self, fd: i32) { self.fa_fd.store(fd, Ordering::Release); }

    /// Resolve the signal to actually deliver for an async-I/O event: the
    /// `F_SETSIG` value if set, else `dfl` (the default `SIGIO`/`SIGURG`).
    /// Linux `send_sigio_to_task`: `signum ? signum : SIGIO`. # C: O(1)
    pub fn fasync_signal(&self, dfl: i32) -> i32 {
        let s = self.f_sig.load(Ordering::Acquire);
        if s != 0 { s } else { dfl }
    }

    /// `O_ASYNC` enabled on this description (Linux `FASYNC` in `f_flags`).
    /// # C: O(1)
    pub fn is_async(&self) -> bool {
        (self.flags().bits() & super::O_ASYNC) != 0
    }

    /// `kill_fasync` per-fd core (Linux `kill_fasync_rcu` -> `send_sigio` ->
    /// `send_sigio_to_task`): deliver the async-ready signal to THIS
    /// description's `f_owner` via the installed SIGIO hook, carrying the full
    /// `_sigpoll` record (si_code / si_band / si_fd) an `F_SETSIG` handler
    /// exists to read. `dfl` = default signal (SIGIO data / SIGURG OOB),
    /// overridden by `F_SETSIG`; `reason` = the `POLL_*` code.
    ///
    /// No-op unless `O_ASYNC` is set, an owner is recorded, and a hook is
    /// installed. SIGURG is suppressed for a description that chose no
    /// `F_SETSIG` signal (Linux `kill_fasync_rcu`: out-of-band data has its own
    /// default signalling and must not fire plain SIGURG at the owner).
    /// # C: O(1)
    pub fn kill_fasync(&self, dfl: i32, reason: i32) {
        /// `SIGURG` (`asm-generic/signal.h`).
        const SIGURG: i32 = 23;
        if !self.is_async() { return; }
        let chosen = self.f_sig.load(Ordering::Acquire);
        if dfl == SIGURG && chosen == 0 { return; }
        let owner = self.owner.load(Ordering::Acquire);
        if owner == 0 { return; }
        let h = SIGIO_HOOK.load(Ordering::Acquire);
        if h == 0 { return; }
        let sig = self.fasync_signal(dfl);
        let (uid, euid) = self.f_owner_creds();
        // SAFETY: h installed by `set_sigio_hook` with the documented
        // fn(AsyncSignal) signature; the cast round-trips that exact type.
        let f: fn(AsyncSignal) = unsafe { core::mem::transmute(h) };
        f(AsyncSignal {
            owner, sig, uid, euid,
            code: sicode_for(sig, reason),
            band: band_for(reason),
            ty:   self.owner_type.load(Ordering::Acquire),
            fd:   self.fa_fd.load(Ordering::Acquire),
            queued: chosen != 0,
        });
    }
}

/// Deliver `reason` to every fasync holder in `list`, with the list lock
/// already dropped — the signal hook takes sched locks. # C: O(N)
pub fn deliver(list: Vec<Arc<File>>, sig: i32, reason: i32) {
    for f in list { f.kill_fasync(sig, reason); }
}
