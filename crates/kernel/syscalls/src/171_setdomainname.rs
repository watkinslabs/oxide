// Global hostname state per `28§4` / sethostname(2). Plain Spinlock-
// guarded byte buffer; uname.nodename + /proc/sys/kernel/hostname
// + sys_sethostname / sys_gethostname read+write it.


use alloc::collections::BTreeMap;
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
static DOMAINNAME: Spinlock<Hostname, TaskListClass> = Spinlock::new(Hostname::empty());
static UTS_NAMES: Spinlock<BTreeMap<u64, (Hostname, Hostname)>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

impl Hostname {
    /// # C: O(1)
    pub const fn empty() -> Self {
        Self { bytes: [0u8; HOST_NAME_MAX], len: 0 }
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

fn hostname_from(bytes: alloc::vec::Vec<u8>) -> Hostname {
    let mut value = Hostname::empty();
    let len = bytes.len().min(HOST_NAME_MAX);
    value.bytes[..len].copy_from_slice(&bytes[..len]);
    value.len = len;
    value
}

/// Allocate UTS state under its canonical namespace identity. # C: O(log N)
pub fn allocate_uts_state(id: u64, hostname: alloc::vec::Vec<u8>, domainname: alloc::vec::Vec<u8>) {
    UTS_NAMES.lock().insert(id, (hostname_from(hostname), hostname_from(domainname)));
}

/// Hostname for UTS namespace `uts_ns` (0 = global statics). # C: O(log N)
pub fn host_for(uts_ns: u64) -> alloc::vec::Vec<u8> {
    if uts_ns == 0 { return snapshot(); }
    UTS_NAMES.lock().get(&uts_ns).map(|(host, _)| host.bytes[..host.len].to_vec())
        .unwrap_or_else(snapshot)
}

/// Domainname for UTS namespace `uts_ns` (0 = global). # C: O(log N)
pub fn dom_for(uts_ns: u64) -> alloc::vec::Vec<u8> {
    if uts_ns == 0 { return domain_snapshot(); }
    UTS_NAMES.lock().get(&uts_ns).map(|(_, dom)| dom.bytes[..dom.len].to_vec())
        .unwrap_or_else(domain_snapshot)
}

/// Set the hostname of UTS namespace `uts_ns` (0 = global). # C: O(log N)
pub fn set_host_for(uts_ns: u64, name: &[u8]) {
    if uts_ns == 0 { set(name); return; }
    if let Some((host, _)) = UTS_NAMES.lock().get_mut(&uts_ns) { *host = hostname_from(name.to_vec()); }
}

/// Set the domainname of UTS namespace `uts_ns` (0 = global). # C: O(log N)
pub fn set_dom_for(uts_ns: u64, name: &[u8]) {
    if uts_ns == 0 { domain_set(name); return; }
    if let Some((_, dom)) = UTS_NAMES.lock().get_mut(&uts_ns) { *dom = hostname_from(name.to_vec()); }
}

/// UTS-namespace id of the running task (0 if none). # C: O(1)
fn current_uts_ns() -> u64 {
    sched::live::current().and_then(|task|
        task.namespace_id(namespace_identity::NamespaceKind::Uts)).unwrap_or(0)
}

/// Hostname for the running task's UTS namespace — the `/proc/sys/kernel/
/// hostname` reader (procfs hook); ns-aware unlike the raw global. # C: O(1)
pub fn snapshot_current() -> alloc::vec::Vec<u8> { host_for(current_uts_ns()) }

/// Set the running task's UTS-namespace hostname — `/proc/sys/kernel/
/// hostname` write hook. # C: O(1)
pub fn set_current(b: &[u8]) { set_host_for(current_uts_ns(), b) }

/// Domainname reader for `/proc/sys/kernel/domainname`. # C: O(1)
pub fn domain_snapshot_current() -> alloc::vec::Vec<u8> {
    let d = dom_for(current_uts_ns());
    if d.is_empty() { b"(none)".to_vec() } else { d }
}

/// Domainname write hook for `/proc/sys/kernel/domainname`. # C: O(1)
pub fn domain_set_current(b: &[u8]) { set_dom_for(current_uts_ns(), b) }

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
    // Write the calling task's UTS namespace (shared by all members);
    // uts_ns 0 = the global domainname.
    let uts_ns = cur.namespace_id(namespace_identity::NamespaceKind::Uts).unwrap_or(0);
    set_dom_for(uts_ns, &buf[..len]);
    0
}
