use core::sync::atomic::{AtomicUsize, Ordering};

pub const DEFAULT_SOMAXCONN: usize = 4096;

static SOMAXCONN: AtomicUsize = AtomicUsize::new(DEFAULT_SOMAXCONN);

/// Current `net.core.somaxconn` value. # C: O(1)
pub fn somaxconn() -> usize { SOMAXCONN.load(Ordering::Acquire) }

/// Update `net.core.somaxconn`. # C: O(1)
pub fn set_somaxconn(value: usize) { SOMAXCONN.store(value, Ordering::Release); }

/// Linux unsigned backlog clamp performed by `__sys_listen_socket`.
/// Negative `i32` values therefore clamp to `somaxconn`. # C: O(1)
pub fn normalize_listen_backlog(backlog: i32, limit: usize) -> usize {
    core::cmp::min(backlog as u32 as usize, limit)
}
