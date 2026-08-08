// The generic socket base every family embeds.
//
// Linux keeps one `struct sock` under every family's socket type, and the
// SOL_SOCKET option state lives there — not in the internet socket, not in a
// second copy on the netlink or virtual-socket types. This module is that one
// base: a family that embeds it gets the whole generic option surface, and the
// admitted write and the read that answers it can never reach different words.
//
// Ungated: the storage and the apply decision must run under hosted
// `cargo test` (`docs/53`).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, Ordering};

use crate::scm::{ScmCredentials, ScmSecurity};
use crate::sock_opts::sol_socket::{self as sol, Scalar, flag};
use crate::sock_opts::sol_socket::set::Action;

/// Generic `struct sock` option state, shared by every socket family. # C: O(1)
#[derive(Debug)]
pub struct SockBase {
    /// Shared with the bind reservation the address ladder consults, so the
    /// switch has one home across a socket and its endpoint.
    pub reuseaddr: Arc<AtomicI32>,
    pub reuseport: Arc<AtomicI32>,
    pub keepalive: AtomicI32,
    pub broadcast: AtomicI32,
    pub oobinline: AtomicI32,
    pub sndbuf: AtomicI32,
    pub rcvbuf: AtomicI32,
    /// `SOCK_RCVBUF_LOCK`: set once a write names a receive size, after which
    /// the transport follows it instead of autotuning.
    pub rcvbuf_locked: AtomicBool,
    /// `sk_sndtimeo` / `sk_rcvtimeo` in nanoseconds; `0` waits forever.
    pub sndtimeo_ns: AtomicI64,
    pub rcvtimeo_ns: AtomicI64,
    pub priority: AtomicI32,
    pub mark: AtomicI32,
    /// `sk_tsflags`: the transmit/receive timestamp report selection.
    pub timestamping: AtomicI32,
    /// `sk_tskey`: the transmit-record key this socket reports next.
    pub tskey: AtomicU32,
    /// `sk_bound_dev_if`: 0 means no bound egress/ingress interface.
    pub bound_ifindex: AtomicU32,
    pub passcred: ScmCredentials,
    pub scm_security: ScmSecurity,
    /// The flag word and indexed scalars the generic table owns.
    pub generic: sol::GenericSockOpts,
}

impl Default for SockBase {
    fn default() -> Self {
        Self::with_buffers(crate::sysctl::DEFAULT_WMEM_DEFAULT as i32,
                           crate::sysctl::DEFAULT_RMEM_DEFAULT as i32)
    }
}

impl SockBase {
    /// A base whose buffer budgets start at family-chosen sizes. # C: O(1)
    pub fn with_buffers(sndbuf: i32, rcvbuf: i32) -> Self {
        Self {
            reuseaddr: Arc::new(AtomicI32::new(0)),
            reuseport: Arc::new(AtomicI32::new(0)),
            keepalive: AtomicI32::new(0),
            broadcast: AtomicI32::new(0),
            oobinline: AtomicI32::new(0),
            sndbuf: AtomicI32::new(sndbuf),
            rcvbuf: AtomicI32::new(rcvbuf),
            rcvbuf_locked: AtomicBool::new(false),
            sndtimeo_ns: AtomicI64::new(0),
            rcvtimeo_ns: AtomicI64::new(0),
            priority: AtomicI32::new(0),
            mark: AtomicI32::new(0),
            timestamping: AtomicI32::new(0),
            tskey: AtomicU32::new(0),
            bound_ifindex: AtomicU32::new(0),
            passcred: ScmCredentials::new(),
            scm_security: ScmSecurity::new(),
            generic: sol::GenericSockOpts::default(),
        }
    }

    /// Send budget in bytes. # C: O(1)
    pub fn sndbuf_bytes(&self) -> usize { self.sndbuf.load(Ordering::Acquire).max(0) as usize }

    /// Receive budget in bytes. # C: O(1)
    pub fn rcvbuf_bytes(&self) -> usize { self.rcvbuf.load(Ordering::Acquire).max(0) as usize }

    /// Publish a receive budget named by something other than the option table.
    /// # C: O(1)
    pub fn set_rcvbuf_bytes(&self, bytes: usize) {
        self.rcvbuf.store(bytes.min(i32::MAX as usize) as i32, Ordering::Release);
    }

    /// `sock_sndtimeo` in nanoseconds, `0` for no timeout. # C: O(1)
    pub fn sndtimeo(&self) -> i64 { self.sndtimeo_ns.load(Ordering::Acquire) }

    /// `sock_rcvtimeo` in nanoseconds, `0` for no timeout. # C: O(1)
    pub fn rcvtimeo(&self) -> i64 { self.rcvtimeo_ns.load(Ordering::Acquire) }

    /// The timeout as the unsigned nanosecond count the wait helpers take.
    /// # C: O(1)
    pub fn sndtimeo_u64(&self) -> u64 { self.sndtimeo().max(0) as u64 }

    /// # C: O(1)
    pub fn rcvtimeo_u64(&self) -> u64 { self.rcvtimeo().max(0) as u64 }

    /// Store one admitted generic write. Returns whether this base owns the
    /// action: the device binding, which must be resolved against the socket's
    /// own namespace first, reports `false` so the caller cannot silently drop
    /// it. # C: O(1)
    pub fn apply(&self, action: Action) -> bool {
        match action {
            Action::Accept => {}
            Action::Flag { bit: flag::SCM_SECURITY, on } => self.scm_security.set(on),
            Action::Flag { bit, on } => self.generic.set_flag(bit, on),
            Action::Reuseaddr(v) => self.reuseaddr.store(v, Ordering::Release),
            Action::Reuseport(v) => self.reuseport.store(v, Ordering::Release),
            Action::Keepalive(v) => self.keepalive.store(v, Ordering::Release),
            Action::Broadcast(v) => self.broadcast.store(v, Ordering::Release),
            Action::Oobinline(v) => self.oobinline.store(v, Ordering::Release),
            Action::SndBuf(v) => self.sndbuf.store(v, Ordering::Release),
            Action::RcvBuf(v) => {
                self.rcvbuf.store(v, Ordering::Release);
                // The write also takes the receive-buffer lock, which stops
                // window autotuning from overriding the requested size.
                self.rcvbuf_locked.store(true, Ordering::Release);
                self.generic.set_scalar(Scalar::BufLock,
                    self.generic.scalar(Scalar::BufLock) | sol::SOCK_RCVBUF_LOCK);
            }
            Action::Priority(v) => self.priority.store(v, Ordering::Release),
            Action::Mark(v) => self.mark.store(v, Ordering::Release),
            Action::Passcred(v) => self.passcred.set(v != 0),
            Action::Timestamping { flags, bind_phc, new } => {
                self.timestamping.store(flags, Ordering::Release);
                self.generic.set_scalar(Scalar::TimestampingBindPhc, bind_phc);
                self.generic.set_flag(flag::TSTAMP_NEW, new);
            }
            Action::RecvTimestamps { on, new, nanoseconds } => {
                self.generic.set_flag(flag::RCVTSTAMP, on);
                self.generic.set_flag(flag::RCVTSTAMPNS, on && nanoseconds);
                if on { self.generic.set_flag(flag::TSTAMP_NEW, new); }
            }
            Action::Linger { on, seconds } => {
                self.generic.set_flag(flag::LINGER, on);
                // The linger time is republished only while the switch is on.
                if on { self.generic.set_scalar(Scalar::LingerSeconds, seconds); }
            }
            Action::Timeout { send: true, ns } => self.sndtimeo_ns.store(ns, Ordering::Release),
            Action::Timeout { send: false, ns } => self.rcvtimeo_ns.store(ns, Ordering::Release),
            Action::Scalar { slot, value } => {
                if slot == Scalar::BufLock {
                    self.rcvbuf_locked.store(value & sol::SOCK_RCVBUF_LOCK != 0, Ordering::Release);
                }
                self.generic.set_scalar(slot, value);
            }
            Action::PacingRate(rate) => self.generic.set_max_pacing_rate(rate),
            Action::TxTime { clockid, deadline_mode, report_errors } => {
                self.generic.set_flag(flag::TXTIME, true);
                self.generic.set_scalar(Scalar::TxTimeClockid, clockid);
                self.generic.set_flag(flag::TXTIME_DEADLINE_MODE, deadline_mode);
                self.generic.set_flag(flag::TXTIME_REPORT_ERRORS, report_errors);
            }
            Action::BindToIfindex(_) => return false,
        }
        true
    }

    /// Publish an interface index the family already resolved. # C: O(1)
    pub fn bind_to_ifindex(&self, index: u32) {
        self.bound_ifindex.store(index, Ordering::Release);
    }

    /// `sock_bindtoindex`: an index names an interface in the socket's own
    /// network namespace or the write is `ENODEV`; index `0` clears the
    /// binding. # C: O(log N)
    pub fn bind_ifindex_in(&self, namespace: u64, index: i32)
        -> Result<(), syscall::errno::Errno>
    {
        if index != 0 {
            let id = crate::NetIfaceId::from_raw(index as u32);
            if crate::sock::stack().ifaces.lookup_in_ns(id, namespace).is_none() {
                return Err(syscall::errno::Errno::Enodev);
            }
        }
        self.bind_to_ifindex(index.max(0) as u32);
        Ok(())
    }

    /// `sock_setbindtodevice`: resolve one interface NAME against the socket's
    /// namespace; an empty name clears the binding. # C: O(N ifaces)
    pub fn bind_device_in(&self, namespace: u64, name: &str)
        -> Result<(), syscall::errno::Errno>
    {
        if name.is_empty() { self.bind_to_ifindex(0); return Ok(()); }
        match crate::sock::stack().ifaces.lookup_name_in_ns(name, namespace) {
            Some((id, _)) => { self.bind_to_ifindex(id.raw()); Ok(()) }
            None => Err(syscall::errno::Errno::Enodev),
        }
    }

    /// Whether a device is already bound, which the re-binding capability
    /// ladder is judged against. # C: O(1)
    pub fn bound_device(&self) -> bool { self.bound_ifindex.load(Ordering::Acquire) != 0 }

    /// `sock_getbindtodevice`: what a `SO_BINDTODEVICE` read answers with.
    /// `None` is the unbound answer — no bytes and a published length of zero.
    /// A bound socket needs a whole `IFNAMSIZ` of room, and that screen runs
    /// BEFORE the interface is resolved, so a short buffer is `EINVAL` rather
    /// than the name's own refusal. # C: O(N ifaces)
    pub fn bound_device_name(&self, namespace: u64, requested: usize)
        -> Result<Option<alloc::string::String>, syscall::errno::Errno>
    {
        if !self.bound_device() { return Ok(None); }
        if requested < sol::set::IFNAMSIZ { return Err(syscall::errno::Errno::Einval); }
        let id = crate::NetIfaceId::from_raw(self.bound_ifindex.load(Ordering::Acquire));
        crate::sock::stack().ifaces.name_in_ns(id, namespace).map(Some)
            .ok_or(syscall::errno::Errno::Enodev)
    }

    /// The admission environment one write is judged against, given the
    /// caller's capabilities and the live buffer ceilings. # C: O(1)
    pub fn set_env(&self, caps: sol::OptCaps) -> sol::set::SetEnv {
        sol::set::SetEnv {
            caps,
            bound_device: self.bound_device(),
            ceilings: crate::sysctl::buf_ceilings(),
            busy_poll_budget: self.generic.scalar(Scalar::BusyPollBudget),
        }
    }
}

#[cfg(test)]
mod tests;
