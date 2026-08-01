// `IPV6_FLOWLABEL_MGR`: the per-namespace flow-label table a socket leases a
// label from, and the label the transmit path then stamps into the header.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use syscall::errno::Errno;
use sync::{Socket as LockClass, Spinlock};

use super::uapi::*;
use crate::sock_opts::sol_socket::OptCaps;

/// Shortest and longest lease an unprivileged caller may ask for, in seconds.
pub const FL_MIN_LINGER: u16 = 6;
pub const FL_MAX_LINGER: u16 = 150;
/// Leases one socket, and one namespace, may hold.
pub const FL_MAX_PER_SOCK: usize = 32;
pub const FL_MAX_SIZE: usize = 8192;

const NSEC_PER_SEC: u64 = 1_000_000_000;

/// `struct in6_flowlabel_req`, already imported. # C: O(1)
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct FlowReq {
    pub dst: [u8; 16],
    pub action: u8,
    pub share: u8,
    pub flags: u16,
    pub expires: u16,
    pub linger: u16,
    pub label: u32,
}

impl FlowReq {
    /// Decode the wire form: a 16-byte destination, the action, the sharing
    /// mode, then three 16-bit fields and the label. # C: O(1)
    pub fn parse(b: &[u8; IN6_FLOWLABEL_REQ_SIZE]) -> Self {
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&b[..16]);
        Self {
            dst,
            action: b[16],
            share: b[17],
            flags: u16::from_ne_bytes([b[18], b[19]]),
            expires: u16::from_ne_bytes([b[20], b[21]]),
            linger: u16::from_ne_bytes([b[22], b[23]]),
            label: u32::from_ne_bytes([b[24], b[25], b[26], b[27]]),
        }
    }

    /// # C: O(1)
    pub fn encode(&self) -> [u8; IN6_FLOWLABEL_REQ_SIZE] {
        let mut out = [0u8; IN6_FLOWLABEL_REQ_SIZE];
        out[..16].copy_from_slice(&self.dst);
        out[16] = self.action;
        out[17] = self.share;
        out[18..20].copy_from_slice(&self.flags.to_ne_bytes());
        out[20..22].copy_from_slice(&self.expires.to_ne_bytes());
        out[22..24].copy_from_slice(&self.linger.to_ne_bytes());
        out[24..28].copy_from_slice(&self.label.to_ne_bytes());
        out
    }
}

/// The identity a `IPV6_FL_S_PROCESS` or `IPV6_FL_S_USER` lease is pinned to.
/// # C: O(1)
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Owner { pub pid: u32, pub uid: u32 }

/// One interned label. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Lease {
    pub label: u32,
    pub dst: [u8; 16],
    pub share: u8,
    pub owner: Owner,
    pub linger_ns: u64,
    pub expires_ns: u64,
    pub users: u32,
}

/// `check_linger`: a request under the floor is raised to it, one over the
/// ceiling needs the network-administration capability. # C: O(1)
pub fn check_linger(seconds: u16, caps: OptCaps) -> Result<u64, Errno> {
    if seconds < FL_MIN_LINGER { return Ok(FL_MIN_LINGER as u64 * NSEC_PER_SEC); }
    if seconds > FL_MAX_LINGER && !caps.net_admin { return Err(Errno::Eperm); }
    Ok(seconds as u64 * NSEC_PER_SEC)
}

/// `fl_create`'s shape screen: the sharing mode must be one this table knows,
/// and the destination may be neither unspecified nor a mapped IPv4 address.
/// # C: O(1)
pub fn admit_create(req: &FlowReq, caps: OptCaps) -> Result<(u64, u64), Errno> {
    let linger = check_linger(req.linger, caps)?;
    let expires = check_linger(req.expires, caps)?;
    if req.dst == [0u8; 16] { return Err(Errno::Einval); }
    if req.dst[..10] == [0u8; 10] && req.dst[10] == 0xff && req.dst[11] == 0xff {
        return Err(Errno::Einval);
    }
    match req.share {
        IPV6_FL_S_EXCL | IPV6_FL_S_ANY | IPV6_FL_S_PROCESS | IPV6_FL_S_USER => {}
        _ => return Err(Errno::Einval),
    }
    Ok((linger, expires))
}

/// Whether an existing lease may be joined by a second holder. # C: O(1)
pub fn shareable(existing: &Lease, want_share: u8, owner: Owner) -> bool {
    if existing.share == IPV6_FL_S_EXCL || existing.share != want_share { return false; }
    match existing.share {
        IPV6_FL_S_PROCESS => existing.owner.pid == owner.pid,
        IPV6_FL_S_USER => existing.owner.uid == owner.uid,
        _ => true,
    }
}

/// Per-namespace label table. # C: O(1)
pub struct FlowLabels { inner: Spinlock<BTreeMap<(u64, u32), Lease>, LockClass> }

impl FlowLabels {
    /// # C: O(1)
    pub const fn new() -> Self { Self { inner: Spinlock::new(BTreeMap::new()) } }

    /// # C: O(log N)
    pub fn lookup(&self, ns: u64, label: u32) -> Option<Lease> {
        self.inner.lock().get(&(ns, label)).copied()
    }

    /// # C: O(N)
    pub fn count(&self, ns: u64) -> usize {
        self.inner.lock().keys().filter(|(n, _)| *n == ns).count()
    }

    /// `mem_check`: an unprivileged caller may not exhaust the table, nor hold
    /// more leases on one socket than the per-socket ceiling. # C: O(N)
    pub fn admit_room(&self, ns: u64, held: usize, caps: OptCaps) -> Result<(), Errno> {
        let used = self.count(ns);
        let room = FL_MAX_SIZE.saturating_sub(used);
        if room > FL_MAX_SIZE - FL_MAX_PER_SOCK { return Ok(()); }
        let unpriv_user_limit = (FL_MAX_SIZE - FL_MAX_SIZE / 4) / 2;
        let tight = held >= FL_MAX_PER_SOCK
            || (held > 0 && room < FL_MAX_SIZE / 2)
            || room < FL_MAX_SIZE / 4
            || used >= unpriv_user_limit;
        if room == 0 || (tight && !caps.net_admin) { return Err(Errno::Enobufs); }
        Ok(())
    }

    /// Intern a lease, taking a reference on an identical label that already
    /// exists. A zero label asks the table to pick an unused one. # C: O(N)
    pub fn intern(&self, ns: u64, mut lease: Lease, pick: impl Fn() -> u32)
        -> Result<Lease, Errno>
    {
        let mut held = self.inner.lock();
        if lease.label == 0 {
            for _ in 0..FL_MAX_SIZE {
                let candidate = pick() & IPV6_FLOWINFO_FLOWLABEL;
                if candidate != 0 && !held.contains_key(&(ns, candidate)) {
                    lease.label = candidate;
                    break;
                }
            }
            if lease.label == 0 { return Err(Errno::Enobufs); }
        }
        if let Some(existing) = held.get_mut(&(ns, lease.label)) {
            existing.users += 1;
            return Ok(*existing);
        }
        held.insert((ns, lease.label), lease);
        Ok(lease)
    }

    /// Drop one holder's reference, freeing the lease when the last goes.
    /// # C: O(log N)
    pub fn release(&self, ns: u64, label: u32) -> bool {
        let mut held = self.inner.lock();
        let Some(lease) = held.get_mut(&(ns, label)) else { return false; };
        lease.users -= 1;
        if lease.users == 0 { held.remove(&(ns, label)); }
        true
    }

    /// `fl6_renew`: extend a lease without ever shortening it. # C: O(log N)
    pub fn renew(&self, ns: u64, label: u32, linger: u64, expires: u64, now: u64)
        -> Result<(), Errno>
    {
        let mut held = self.inner.lock();
        let Some(lease) = held.get_mut(&(ns, label)) else { return Err(Errno::Esrch); };
        if lease.linger_ns < linger { lease.linger_ns = linger; }
        let expires = expires.max(lease.linger_ns);
        if lease.expires_ns < now + expires { lease.expires_ns = now + expires; }
        Ok(())
    }

    /// Retire every lease whose lifetime has run out. # C: O(N)
    pub fn expire(&self, now: u64) {
        self.inner.lock().retain(|_, lease| lease.expires_ns > now);
    }

    /// Every label a namespace holds, for teardown. # C: O(N)
    pub fn labels_in(&self, ns: u64) -> Vec<u32> {
        self.inner.lock().keys().filter(|(n, _)| *n == ns).map(|(_, l)| *l).collect()
    }
}

/// The namespace-wide table. # C: O(1)
pub fn table() -> &'static FlowLabels {
    static TABLE: FlowLabels = FlowLabels::new();
    &TABLE
}
