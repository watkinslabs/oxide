use core::sync::atomic::{AtomicUsize, Ordering};

pub const DEFAULT_SOMAXCONN: usize = 4096;

static SOMAXCONN: AtomicUsize = AtomicUsize::new(DEFAULT_SOMAXCONN);

/// `net.core.somaxconn` value in `ns`. # C: O(log N)
pub fn somaxconn_in(ns: u64) -> usize {
    if ns == 0 {
        SOMAXCONN.load(Ordering::Acquire)
    } else {
        crate::net_ns::ns_net(ns).somaxconn.load(Ordering::Acquire)
    }
}

/// Update `net.core.somaxconn` in `ns`. # C: O(log N)
pub fn set_somaxconn_in(ns: u64, value: usize) {
    if ns == 0 {
        SOMAXCONN.store(value, Ordering::Release);
    } else {
        crate::net_ns::ns_net(ns).somaxconn.store(value, Ordering::Release);
    }
}

/// Current task's `net.core.somaxconn` value. # C: O(log N)
pub fn somaxconn() -> usize { somaxconn_in(crate::netdev::current_net_ns()) }

/// Update current task's `net.core.somaxconn`. # C: O(log N)
pub fn set_somaxconn(value: usize) {
    set_somaxconn_in(crate::netdev::current_net_ns(), value);
}

/// Linux unsigned backlog clamp performed by `__sys_listen_socket`.
/// Negative `i32` values therefore clamp to `somaxconn`. # C: O(1)
pub fn normalize_listen_backlog(backlog: i32, limit: usize) -> usize {
    core::cmp::min(backlog as u32 as usize, limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn somaxconn_is_isolated_per_net_ns() {
        let ns1 = 0x8120_0001;
        let ns2 = 0x8120_0002;

        assert_eq!(somaxconn_in(ns1), DEFAULT_SOMAXCONN);
        assert_eq!(somaxconn_in(ns2), DEFAULT_SOMAXCONN);
        set_somaxconn_in(ns1, 128);
        set_somaxconn_in(ns2, 256);
        assert_eq!(somaxconn_in(ns1), 128);
        assert_eq!(somaxconn_in(ns2), 256);
    }
}
