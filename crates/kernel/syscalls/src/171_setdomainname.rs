// Global hostname state per `28§4` / sethostname(2). Plain Spinlock-
// guarded byte buffer; uname.nodename + /proc/sys/kernel/hostname
// + sys_sethostname / sys_gethostname read+write it.


use namespace_identity::{NamespaceKind, NamespaceRef};
use sync::{Spinlock, TaskList as TaskListClass};

/// Linux HOST_NAME_MAX (no trailing NUL).
pub const HOST_NAME_MAX: usize = 64;

/// Hostname slot. Stores the byte length + up to HOST_NAME_MAX
/// bytes; trailing NUL is implicit.
pub struct Hostname {
    pub bytes: [u8; HOST_NAME_MAX],
    pub len:   usize,
}

impl Hostname {
    /// # C: O(1)
    pub const fn new() -> Self {
        let mut b = [0u8; HOST_NAME_MAX];
        b[0] = b'o'; b[1] = b'x'; b[2] = b'i'; b[3] = b'd'; b[4] = b'e';
        Self { bytes: b, len: 5 }
    }
}

static HOSTNAME: Spinlock<Hostname, TaskListClass> = Spinlock::new(Hostname::new());

/// Snapshot the current hostname into a heap-allocated Vec.
/// # C: O(N)
pub fn snapshot() -> alloc::vec::Vec<u8> {
    let g = HOSTNAME.lock();
    g.bytes[..g.len].to_vec()
}

/// Replace the hostname. Trims to HOST_NAME_MAX bytes; trailing
/// newlines (from /proc/sys/kernel/hostname writes) are stripped
/// via `vfs::path::trim_hostname` (hosted-tested).
/// # C: O(N)
pub fn set(new: &[u8]) {
    let trimmed = vfs::path::trim_hostname(new, HOST_NAME_MAX);
    let mut g = HOSTNAME.lock();
    let end = trimmed.len();
    g.bytes[..end].copy_from_slice(trimmed);
    for i in end..g.len { g.bytes[i] = 0; }
    g.len = end;
}

/// NIS/YP domain name slot. Same shape as hostname; read by
/// uname.domainname + /proc/sys/kernel/domainname; written by
/// `setdomainname(2)`.
static DOMAINNAME: Spinlock<Hostname, TaskListClass> = Spinlock::new(Hostname::none_seed());

impl Hostname {
    /// Linux `init_uts_ns` seeds `nodename`/`domainname` with `UTS_NODENAME` /
    /// `UTS_DOMAINNAME`, both the literal `(none)`. Storing the seed (rather
    /// than substituting `(none)` at every read) keeps ONE source of truth: a
    /// caller that deliberately sets an EMPTY domain then reads an empty
    /// domain, exactly as Linux does. # C: O(1)
    pub const fn none_seed() -> Self {
        let mut b = [0u8; HOST_NAME_MAX];
        b[0] = b'('; b[1] = b'n'; b[2] = b'o'; b[3] = b'n'; b[4] = b'e'; b[5] = b')';
        Self { bytes: b, len: 6 }
    }
}

/// Snapshot the current domain name.
/// # C: O(N)
pub fn domain_snapshot() -> alloc::vec::Vec<u8> {
    let g = DOMAINNAME.lock();
    g.bytes[..g.len].to_vec()
}

/// Replace the domain name. Same trim/clear discipline as `set`.
/// # C: O(N)
pub fn domain_set(new: &[u8]) {
    let trimmed = vfs::path::trim_hostname(new, HOST_NAME_MAX);
    let mut g = DOMAINNAME.lock();
    let end = trimmed.len();
    g.bytes[..end].copy_from_slice(trimmed);
    for i in end..g.len { g.bytes[i] = 0; }
    g.len = end;
}

/// Hostname for one exact UTS owner, mapping init to the global static. # C: O(log N)
pub fn host_for(owner: &NamespaceRef) -> Result<alloc::vec::Vec<u8>, nscg::uts_ns::UtsError> {
    match nscg::uts_ns::snapshot(owner) {
        Ok(names) => Ok(names.hostname),
        Err(nscg::uts_ns::UtsError::InitialOwner) => Ok(snapshot()),
        Err(error) => Err(error),
    }
}

/// Domainname for one exact UTS owner, mapping init to the global static. # C: O(log N)
pub fn dom_for(owner: &NamespaceRef) -> Result<alloc::vec::Vec<u8>, nscg::uts_ns::UtsError> {
    match nscg::uts_ns::snapshot(owner) {
        Ok(names) => Ok(names.domainname),
        Err(nscg::uts_ns::UtsError::InitialOwner) => Ok(domain_snapshot()),
        Err(error) => Err(error),
    }
}

/// Set hostname for one exact UTS owner, mapping init to the global static. # C: O(log N)
pub fn set_host_for(owner: &NamespaceRef, name: &[u8]) -> Result<(), nscg::uts_ns::UtsError> {
    let trimmed = vfs::path::trim_hostname(name, HOST_NAME_MAX);
    match nscg::uts_ns::set_hostname(owner, trimmed.to_vec()) {
        Err(nscg::uts_ns::UtsError::InitialOwner) => { set(trimmed); Ok(()) }
        result => result,
    }
}

/// Set domainname for one exact UTS owner, mapping init to the global static. # C: O(log N)
pub fn set_dom_for(owner: &NamespaceRef, name: &[u8]) -> Result<(), nscg::uts_ns::UtsError> {
    let trimmed = vfs::path::trim_hostname(name, HOST_NAME_MAX);
    match nscg::uts_ns::set_domainname(owner, trimmed.to_vec()) {
        Err(nscg::uts_ns::UtsError::InitialOwner) => { domain_set(trimmed); Ok(()) }
        result => result,
    }
}

fn current_uts_owner() -> Option<NamespaceRef> {
    sched::live::current().and_then(|task| task.namespace_owner(NamespaceKind::Uts))
}

/// Hostname for the running task's UTS namespace — the `/proc/sys/kernel/
/// hostname` reader (procfs hook); ns-aware unlike the raw global. # C: O(1)
pub fn snapshot_current() -> alloc::vec::Vec<u8> {
    current_uts_owner().and_then(|owner| host_for(&owner).ok()).unwrap_or_default()
}

/// Set the running task's UTS-namespace hostname — `/proc/sys/kernel/
/// hostname` write hook. # C: O(1)
pub fn set_current(b: &[u8]) {
    if let Some(owner) = current_uts_owner() { let _ = set_host_for(&owner, b); }
}

/// Domainname reader for `/proc/sys/kernel/domainname`. Reports the stored
/// value verbatim — the `(none)` default lives in the storage seed
/// ([`Hostname::none_seed`]), not in this reader. # C: O(1)
pub fn domain_snapshot_current() -> alloc::vec::Vec<u8> {
    current_uts_owner().and_then(|owner| dom_for(&owner).ok()).unwrap_or_default()
}

/// Domainname write hook for `/proc/sys/kernel/domainname`. # C: O(1)
pub fn domain_set_current(b: &[u8]) {
    if let Some(owner) = current_uts_owner() { let _ = set_dom_for(&owner, b); }
}

/// `sys_setdomainname(name, len)` — slot 171. Mirror of sethostname
/// for the NIS/YP domain name slot.
/// # C: O(N)
pub fn sys_setdomainname(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let ptr = args.a0;
    let len = args.a1 as usize;
    if len > HOST_NAME_MAX { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    if !cur.has_cap(sched::cap::SYS_ADMIN) { return -(Errno::Eperm.as_i32() as i64); }
    if len != 0 {
        if let Err(rv) = crate::userbuf::validate_user_buf(ptr, len as u64, 1) { return rv; }
    }
    let mut buf = [0u8; HOST_NAME_MAX];
    // SAFETY: nonzero source range was validated readable; Linux copyin accepts byte-granular storage.
    unsafe {
        for i in 0..len { buf[i] = core::ptr::read_unaligned((ptr + i as u64) as *const u8); }
    }
    let owner = match cur.namespace_owner(NamespaceKind::Uts) {
        Some(owner) => owner, None => return -(Errno::Esrch.as_i32() as i64),
    };
    match set_dom_for(&owner, &buf[..len]) {
        Ok(()) => 0,
        Err(_) => -(Errno::Eio.as_i32() as i64),
    }
}
