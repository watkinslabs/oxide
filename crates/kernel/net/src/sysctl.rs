use network_namespace::NetworkNamespaceRef;

use crate::net_ns::NetSysctlKey;

pub const DEFAULT_SOMAXCONN: usize = 4096;
pub const DEFAULT_OPTMEM_MAX: usize = 131_072;

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
