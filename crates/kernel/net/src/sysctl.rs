use core::sync::atomic::{AtomicI64, Ordering};

use network_namespace::NetworkNamespaceRef;

use crate::net_ns::NetSysctlKey;

pub const DEFAULT_SOMAXCONN: usize = 4096;
pub const DEFAULT_OPTMEM_MAX: usize = 131_072;
/// `net.core.wmem_max` / `net.core.rmem_max` compiled defaults.
pub const DEFAULT_WMEM_MAX: u32 = 4 << 20;
pub const DEFAULT_RMEM_MAX: u32 = 4 << 20;
/// `SOCK_MIN_SNDBUF` / `SOCK_MIN_RCVBUF` — the write floors on both leaves and
/// the floor `SO_SNDBUF` / `SO_RCVBUF` clamp up to.
pub const SOCK_MIN_SNDBUF: i32 = 4608;
pub const SOCK_MIN_RCVBUF: i32 = 2304;

/// The two send/receive ceilings are ONE global pair, not per-namespace state:
/// only the initial network namespace may write them and every namespace reads
/// the same number.
static WMEM_MAX: AtomicI64 = AtomicI64::new(DEFAULT_WMEM_MAX as i64);
static RMEM_MAX: AtomicI64 = AtomicI64::new(DEFAULT_RMEM_MAX as i64);

/// Write window for both ceilings: floored at the protocol minimum, unbounded
/// above beyond the `int` the leaf is stored in. # C: O(1)
pub const WMEM_MAX_BOUNDS: (i64, i64) = (SOCK_MIN_SNDBUF as i64, i32::MAX as i64);
pub const RMEM_MAX_BOUNDS: (i64, i64) = (SOCK_MIN_RCVBUF as i64, i32::MAX as i64);

/// `net.core.wmem_max`. # C: O(1)
pub fn wmem_max() -> u32 { WMEM_MAX.load(Ordering::Acquire) as u32 }

/// `net.core.rmem_max`. # C: O(1)
pub fn rmem_max() -> u32 { RMEM_MAX.load(Ordering::Acquire) as u32 }

/// # C: O(1)
pub fn set_wmem_max(value: i64) { WMEM_MAX.store(value, Ordering::Release); }

/// # C: O(1)
pub fn set_rmem_max(value: i64) { RMEM_MAX.store(value, Ordering::Release); }

/// The live `net.core.wmem_max` / `net.core.rmem_max` pair one option write
/// clamps against. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BufCeilings { pub wmem_max: u32, pub rmem_max: u32 }

impl Default for BufCeilings {
    fn default() -> Self { Self { wmem_max: DEFAULT_WMEM_MAX, rmem_max: DEFAULT_RMEM_MAX } }
}

/// The ceilings `SO_SNDBUF` / `SO_RCVBUF` clamp against, read once per call so
/// one write cannot be observed half-applied. # C: O(1)
pub fn buf_ceilings() -> BufCeilings {
    BufCeilings { wmem_max: wmem_max(), rmem_max: rmem_max() }
}

/// Read canonical sysctl state owned by a retained namespace. # C: O(log N)
pub fn value(namespace: &NetworkNamespaceRef, key: NetSysctlKey) -> Option<i64> {
    crate::net_ns::state_for(namespace).map(|state| state.sysctls.get(key))
}

/// Update canonical sysctl state owned by a retained namespace. # C: O(log N)
pub fn set_value(namespace: &NetworkNamespaceRef, key: NetSysctlKey,
    value: i64) -> Result<(), ()>
{
    let state = crate::net_ns::state_for(namespace).ok_or(())?;
    state.sysctls.set(key, value);
    Ok(())
}

/// Read a live namespace by numeric key without creating state. # C: O(log N)
pub fn value_in(ns: u64, key: NetSysctlKey) -> Option<i64> {
    crate::net_ns::state_by_id(ns).map(|state| state.sysctls.get(key))
}

/// Update a live namespace by numeric key without creating state. # C: O(log N)
pub fn set_value_in(ns: u64, key: NetSysctlKey, value: i64) -> Result<(), ()> {
    let state = crate::net_ns::state_by_id(ns).ok_or(())?;
    state.sysctls.set(key, value);
    Ok(())
}

/// `net.core.optmem_max` in a live namespace. # C: O(log N)
pub fn optmem_max_in(ns: u64) -> Option<usize> {
    value_in(ns, NetSysctlKey::OptmemMax).map(|value| value as usize)
}

/// Update `net.core.optmem_max` in a live namespace. # C: O(log N)
pub fn set_optmem_max_in(ns: u64, value: usize) -> Result<(), ()> {
    set_value_in(ns, NetSysctlKey::OptmemMax, value as i64)
}

/// Current task's `net.core.optmem_max`. # C: O(log N)
pub fn optmem_max() -> usize {
    let namespace = crate::net_ns::current_namespace();
    crate::net_ns::materialize_state(&namespace).sysctls.get(NetSysctlKey::OptmemMax) as usize
}

/// Update current task's `net.core.optmem_max`. # C: O(log N)
pub fn set_optmem_max(value: usize) -> Result<(), ()> {
    let namespace = crate::net_ns::current_namespace();
    crate::net_ns::materialize_state(&namespace).sysctls.set(NetSysctlKey::OptmemMax, value as i64);
    Ok(())
}

/// `net.core.somaxconn` in a live namespace. # C: O(log N)
pub fn somaxconn_in(ns: u64) -> Option<usize> {
    value_in(ns, NetSysctlKey::Somaxconn).map(|value| value as usize)
}

/// Update `net.core.somaxconn` in a live namespace. # C: O(log N)
pub fn set_somaxconn_in(ns: u64, value: usize) -> Result<(), ()> {
    set_value_in(ns, NetSysctlKey::Somaxconn, value as i64)
}

/// Current task's `net.core.somaxconn`. # C: O(log N)
pub fn somaxconn() -> usize {
    let namespace = crate::net_ns::current_namespace();
    crate::net_ns::materialize_state(&namespace).sysctls.get(NetSysctlKey::Somaxconn) as usize
}

/// Update current task's `net.core.somaxconn`. # C: O(log N)
pub fn set_somaxconn(value: usize) -> Result<(), ()> {
    let namespace = crate::net_ns::current_namespace();
    crate::net_ns::materialize_state(&namespace).sysctls.set(NetSysctlKey::Somaxconn, value as i64);
    Ok(())
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
    fn buf_ceilings_are_global_and_default_to_the_compiled_maximums() {
        let saved = (wmem_max(), rmem_max());
        set_wmem_max(DEFAULT_WMEM_MAX as i64);
        set_rmem_max(DEFAULT_RMEM_MAX as i64);
        assert_eq!(buf_ceilings().wmem_max, DEFAULT_WMEM_MAX);
        assert_eq!(buf_ceilings().rmem_max, DEFAULT_RMEM_MAX);
        set_wmem_max(SOCK_MIN_SNDBUF as i64);
        assert_eq!(buf_ceilings().wmem_max, SOCK_MIN_SNDBUF as u32);
        set_wmem_max(saved.0 as i64);
        set_rmem_max(saved.1 as i64);
    }

    #[test]
    fn buf_ceiling_write_windows_floor_at_the_protocol_minimum() {
        assert_eq!(WMEM_MAX_BOUNDS, (SOCK_MIN_SNDBUF as i64, i32::MAX as i64));
        assert_eq!(RMEM_MAX_BOUNDS, (SOCK_MIN_RCVBUF as i64, i32::MAX as i64));
    }

    fn namespace() -> NetworkNamespaceRef {
        let namespace = crate::net_ns::test_support::allocate_namespace();
        crate::net_ns::materialize_state(&namespace);
        namespace
    }

    #[test]
    fn net_sysctls_are_isolated_per_owner() {
        let first = namespace();
        let second = namespace();
        let a = first.id().as_u64();
        let b = second.id().as_u64();
        set_somaxconn_in(a, 128).unwrap();
        set_somaxconn_in(b, 256).unwrap();
        set_optmem_max_in(a, 65_536).unwrap();
        assert_eq!(somaxconn_in(a), Some(128));
        assert_eq!(somaxconn_in(b), Some(256));
        assert_eq!(optmem_max_in(a), Some(65_536));
        assert_eq!(optmem_max_in(b), Some(DEFAULT_OPTMEM_MAX));
    }

    #[test]
    fn invented_or_dead_ids_do_not_create_state() {
        assert_eq!(somaxconn_in(u64::MAX), None);
        assert!(set_somaxconn_in(u64::MAX, 1).is_err());
        assert!(crate::net_ns::state_by_id(u64::MAX).is_none());
    }
}
