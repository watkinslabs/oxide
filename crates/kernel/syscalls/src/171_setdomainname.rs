// Global hostname state per `28§4` / sethostname(2). Plain Spinlock-
// guarded byte buffer; uname.nodename + /proc/sys/kernel/hostname
// + sys_sethostname / sys_gethostname read+write it.


use namespace_identity::{NamespaceKind, NamespaceRef};
use sync::{Spinlock, TaskList as TaskListClass};

/// Linux `HOST_NAME_MAX` / `__NEW_UTS_LEN` (no trailing NUL). One constant, in
/// the module that owns the syscall's length contract.
pub const HOST_NAME_MAX: usize = crate::uts_policy::NEW_UTS_LEN;

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

/// Replace the init namespace's hostname VERBATIM (clamped to HOST_NAME_MAX).
/// `sethostname(2)` stores exactly the `len` bytes it copied — Linux does a
/// plain `memcpy(u->nodename, tmp, len)` with no filtering — so the newline
/// stripping belongs to the `/proc/sys/kernel/hostname` write hook
/// ([`set_current`]), not here.
/// # C: O(N)
pub fn set(new: &[u8]) {
    let end = core::cmp::min(new.len(), HOST_NAME_MAX);
    let mut g = HOSTNAME.lock();
    g.bytes[..end].copy_from_slice(&new[..end]);
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

/// Replace the init namespace's domain name. Same verbatim/clear discipline
/// as [`set`].
/// # C: O(N)
pub fn domain_set(new: &[u8]) {
    let end = core::cmp::min(new.len(), HOST_NAME_MAX);
    let mut g = DOMAINNAME.lock();
    g.bytes[..end].copy_from_slice(&new[..end]);
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

/// Set hostname for one exact UTS owner, mapping init to the global static.
/// Stores the bytes VERBATIM (clamped) — see [`set`]. # C: O(log N)
pub fn set_host_for(owner: &NamespaceRef, name: &[u8]) -> Result<(), nscg::uts_ns::UtsError> {
    let name = &name[..core::cmp::min(name.len(), HOST_NAME_MAX)];
    match nscg::uts_ns::set_hostname(owner, name.to_vec()) {
        Err(nscg::uts_ns::UtsError::InitialOwner) => { set(name); Ok(()) }
        result => result,
    }
}

/// Set domainname for one exact UTS owner, mapping init to the global static.
/// # C: O(log N)
pub fn set_dom_for(owner: &NamespaceRef, name: &[u8]) -> Result<(), nscg::uts_ns::UtsError> {
    let name = &name[..core::cmp::min(name.len(), HOST_NAME_MAX)];
    match nscg::uts_ns::set_domainname(owner, name.to_vec()) {
        Err(nscg::uts_ns::UtsError::InitialOwner) => { domain_set(name); Ok(()) }
        result => result,
    }
}

fn current_uts_owner() -> Option<NamespaceRef> {
    sched::live::current().and_then(|task| task.namespace_owner(NamespaceKind::Uts))
}

/// Hostname for the running task's UTS namespace — the `/proc/sys/kernel/
/// hostname` reader (procfs hook); ns-aware unlike the raw global. # C: O(1)
pub fn snapshot_current() -> alloc::vec::Vec<u8> {
    // No current task / no UTS owner (early boot, kthreads) means the INIT
    // namespace, whose value lives in the global static — not "empty".
    // Linux reads init_uts_ns there. `unwrap_or_default()` returned an empty
    // string instead, which is a different answer, not a missing one.
    current_uts_owner().and_then(|owner| host_for(&owner).ok()).unwrap_or_else(snapshot)
}

/// Set the running task's UTS-namespace hostname — `/proc/sys/kernel/hostname`
/// write hook. THIS is where the trailing newline a `echo host > …` write
/// carries is stripped (Linux `proc_dostring`); the syscall path stores
/// verbatim. Absent owner means the init namespace, whose value is the global
/// static — the same fallback the reader uses, so the two cannot disagree.
/// # C: O(1)
pub fn set_current(b: &[u8]) {
    let trimmed = vfs::path::trim_hostname(b, HOST_NAME_MAX);
    match current_uts_owner() {
        Some(owner) => { let _ = set_host_for(&owner, trimmed); }
        None => set(trimmed),
    }
}

/// Domainname reader for `/proc/sys/kernel/domainname`. Reports the stored
/// value verbatim — the `(none)` default lives in the storage seed
/// ([`Hostname::none_seed`]), not in this reader. # C: O(1)
pub fn domain_snapshot_current() -> alloc::vec::Vec<u8> {
    // Same as the hostname reader: absent owner => init namespace, whose
    // domainname is seeded `(none)` by `Hostname::none_seed`. An owner that
    // DOES exist still reports its stored value verbatim, so
    // `setdomainname("")` keeps reporting empty as Linux does.
    current_uts_owner().and_then(|owner| dom_for(&owner).ok()).unwrap_or_else(domain_snapshot)
}

/// Domainname write hook for `/proc/sys/kernel/domainname`. Same newline-strip
/// and init fallback as [`set_current`]. # C: O(1)
pub fn domain_set_current(b: &[u8]) {
    let trimmed = vfs::path::trim_hostname(b, HOST_NAME_MAX);
    match current_uts_owner() {
        Some(owner) => { let _ = set_dom_for(&owner, trimmed); }
        None => domain_set(trimmed),
    }
}

/// Which `new_utsname` field a UTS write targets. `sethostname(2)` and
/// `setdomainname(2)` are the same syscall in Linux apart from this.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum UtsField { Nodename, Domainname }

/// Shared body of `SYSCALL_DEFINE2(sethostname)` / `SYSCALL_DEFINE2(
/// setdomainname)` (Linux `kernel/sys.c`). The decision order lives in
/// [`crate::uts_policy::check_uts_set`]; this owns the copy-in and the store.
/// # C: O(N)
pub fn write_uts_name(args: &syscall::SyscallArgs, field: UtsField) -> i64 {
    use syscall::errno::Errno;
    let ptr = args.a0;
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    let owner = match cur.namespace_owner(NamespaceKind::Uts) {
        Some(owner) => owner, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // Linux `ns_capable(current->nsproxy->uts_ns->user_ns, CAP_SYS_ADMIN)`: the
    // capability is required in the user namespace that OWNS the UTS namespace
    // being written, NOT merely present in the caller's effective set. Without
    // the scoping, a task that unshared a user namespace could rename the host.
    let permitted = nscg::proc_ns::has_cap_for(&cur, &owner.owner_user_namespace(),
        sched::cap::SYS_ADMIN);
    let len = match crate::uts_policy::check_uts_set(args.a1, permitted) {
        Ok(len) => len,
        Err(e)  => return -(e.as_i32() as i64),
    };
    if len != 0 {
        if let Err(rv) = crate::userbuf::validate_user_buf(ptr, len as u64, 1) { return rv; }
    }
    let mut buf = [0u8; HOST_NAME_MAX];
    // SAFETY: nonzero source range was validated readable; Linux copyin accepts byte-granular storage.
    unsafe {
        for i in 0..len { buf[i] = core::ptr::read_unaligned((ptr + i as u64) as *const u8); }
    }
    // Stored verbatim: Linux `memcpy(u->nodename, tmp, len)` filters nothing.
    let stored = match field {
        UtsField::Nodename   => set_host_for(&owner, &buf[..len]),
        UtsField::Domainname => set_dom_for(&owner, &buf[..len]),
    };
    match stored { Ok(()) => 0, Err(_) => -(Errno::Eio.as_i32() as i64) }
}

/// `sys_setdomainname(name, len)` — slot 171. # C: O(N)
pub fn sys_setdomainname(args: &syscall::SyscallArgs) -> i64 {
    write_uts_name(args, UtsField::Domainname)
}

