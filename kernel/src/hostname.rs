// Global hostname state per `28§4` / sethostname(2). Plain Spinlock-
// guarded byte buffer; uname.nodename + /proc/sys/kernel/hostname
// + sys_sethostname / sys_gethostname read+write it.

#![cfg(target_os = "oxide-kernel")]

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
/// newlines (from /proc/sys/kernel/hostname writes) are stripped.
/// # C: O(N)
pub fn set(new: &[u8]) {
    let mut g = HOSTNAME.lock();
    let mut end = new.len().min(HOST_NAME_MAX);
    while end > 0 && (new[end - 1] == b'\n' || new[end - 1] == 0) { end -= 1; }
    g.bytes[..end].copy_from_slice(&new[..end]);
    for i in end..g.len { g.bytes[i] = 0; }
    g.len = end;
}
