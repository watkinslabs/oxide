// Global hostname state per `28§4` / sethostname(2). Plain Spinlock-
// guarded byte buffer; uname.nodename + /proc/sys/kernel/hostname
// + sys_sethostname / sys_gethostname read+write it.


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

/// `sys_setdomainname(name, len)` — slot 171. Mirror of sethostname
/// for the NIS/YP domain name slot.
/// # C: O(N)
pub fn sys_setdomainname(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let ptr = args.a0;
    let len = args.a1 as usize;
    if len > HOST_NAME_MAX { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = crate::syscalls::validate_user_buf(ptr, len as u64, 1) { return rv; }
    let mut buf = [0u8; HOST_NAME_MAX];
    // SAFETY: ptr range validated < USER_VA_END by validate_user_buf above; CPL=0 byte read through caller's AS for `len` bytes.
    unsafe {
        for i in 0..len { buf[i] = core::ptr::read_volatile((ptr + i as u64) as *const u8); }
    }
    domain_set(&buf[..len]);
    0
}
