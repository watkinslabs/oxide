use core::sync::atomic::{AtomicI64, Ordering};

use network_namespace::NetworkNamespaceRef;

use crate::net_ns::{BufWindow as NetWindow, NetSysctlKey};

pub const DEFAULT_SOMAXCONN: usize = 4096;
pub const DEFAULT_OPTMEM_MAX: usize = 131_072;
/// `net.core.wmem_max` / `net.core.rmem_max` compiled defaults.
pub const DEFAULT_WMEM_MAX: u32 = 4 << 20;
pub const DEFAULT_RMEM_MAX: u32 = 4 << 20;
/// `SOCK_MIN_SNDBUF` / `SOCK_MIN_RCVBUF` — the write floors on both leaves and
/// the floor `SO_SNDBUF` / `SO_RCVBUF` clamp up to.
pub const SOCK_MIN_SNDBUF: i32 = 4608;
pub const SOCK_MIN_RCVBUF: i32 = 2304;

/// `net.core.wmem_default` / `net.core.rmem_default` compiled defaults: the
/// buffer every socket starts with unless its protocol overrides it. The
/// number is the per-skb overhead of a 256-byte frame times 256 frames on this
/// ABI, which is the same 212992 a reference kernel reports on x86_64.
pub const DEFAULT_WMEM_DEFAULT: u32 = 212_992;
pub const DEFAULT_RMEM_DEFAULT: u32 = 212_992;

/// `net.ipv4.tcp_wmem` / `net.ipv4.tcp_rmem` compiled defaults, indexed by
/// `net_ns::BufWindow`. TCP overrides the generic defaults above at socket
/// creation, which is why a fresh TCP socket reports a far smaller send buffer
/// than a fresh datagram or AF_UNIX socket.
pub const DEFAULT_TCP_WMEM: [i64; 3] = [4_096, 16_384, 4 << 20];
pub const DEFAULT_TCP_RMEM: [i64; 3] = [4_096, 131_072, 6 << 20];

/// The two send/receive ceilings are ONE global pair, not per-namespace state:
/// only the initial network namespace may write them and every namespace reads
/// the same number.
static WMEM_MAX: AtomicI64 = AtomicI64::new(DEFAULT_WMEM_MAX as i64);
static RMEM_MAX: AtomicI64 = AtomicI64::new(DEFAULT_RMEM_MAX as i64);
/// `wmem_default` / `rmem_default` are globals for the same reason the
/// ceilings are.
static WMEM_DEFAULT: AtomicI64 = AtomicI64::new(DEFAULT_WMEM_DEFAULT as i64);
static RMEM_DEFAULT: AtomicI64 = AtomicI64::new(DEFAULT_RMEM_DEFAULT as i64);

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

/// Write windows for the two default leaves: the same protocol floors the
/// ceilings use, unbounded above beyond the `int` they are stored in. # C: O(1)
pub const WMEM_DEFAULT_BOUNDS: (i64, i64) = (SOCK_MIN_SNDBUF as i64, i32::MAX as i64);
pub const RMEM_DEFAULT_BOUNDS: (i64, i64) = (SOCK_MIN_RCVBUF as i64, i32::MAX as i64);
/// `net.ipv4.tcp_wmem` / `tcp_rmem` accept any positive `int`. # C: O(1)
pub const TCP_MEM_BOUNDS: (i64, i64) = (1, i32::MAX as i64);

/// `net.core.wmem_default`. # C: O(1)
pub fn wmem_default() -> u32 { WMEM_DEFAULT.load(Ordering::Acquire) as u32 }

/// `net.core.rmem_default`. # C: O(1)
pub fn rmem_default() -> u32 { RMEM_DEFAULT.load(Ordering::Acquire) as u32 }

/// # C: O(1)
pub fn set_wmem_default(value: i64) { WMEM_DEFAULT.store(value, Ordering::Release); }

/// # C: O(1)
pub fn set_rmem_default(value: i64) { RMEM_DEFAULT.store(value, Ordering::Release); }

/// `net.ipv4.tcp_wmem` in a live namespace, innermost-first order. # C: O(log N)
pub fn tcp_wmem_in(ns: u64) -> Option<[i64; 3]> { buf_window_in(ns, false) }

/// `net.ipv4.tcp_rmem` in a live namespace. # C: O(log N)
pub fn tcp_rmem_in(ns: u64) -> Option<[i64; 3]> { buf_window_in(ns, true) }

fn buf_window_in(ns: u64, receive: bool) -> Option<[i64; 3]> {
    let state = crate::net_ns::state_by_id(ns)?;
    let mut window = [0i64; 3];
    for (slot, out) in [NetWindow::Min, NetWindow::Default, NetWindow::Max]
        .into_iter().zip(window.iter_mut())
    {
        *out = state.sysctls.get(if receive {
            NetSysctlKey::TcpRmem(slot)
        } else {
            NetSysctlKey::TcpWmem(slot)
        });
    }
    Some(window)
}

/// Update one slot of `net.ipv4.tcp_wmem` / `tcp_rmem`. # C: O(log N)
pub fn set_tcp_buf_window(namespace: &NetworkNamespaceRef, receive: bool,
    window: [i64; 3]) -> Result<(), ()>
{
    let state = crate::net_ns::state_for(namespace).ok_or(())?;
    for (slot, value) in [NetWindow::Min, NetWindow::Default, NetWindow::Max]
        .into_iter().zip(window)
    {
        state.sysctls.set(if receive {
            NetSysctlKey::TcpRmem(slot)
        } else {
            NetSysctlKey::TcpWmem(slot)
        }, value);
    }
    Ok(())
}

/// `net.ipv4.tcp_wmem` / `tcp_rmem` for a retained namespace, materializing
/// its state so a fresh namespace reports the compiled window. # C: O(log N)
pub fn tcp_buf_window(namespace: &NetworkNamespaceRef, receive: bool) -> [i64; 3] {
    let state = crate::net_ns::materialize_state(namespace);
    let mut window = [0i64; 3];
    for (slot, out) in [NetWindow::Min, NetWindow::Default, NetWindow::Max]
        .into_iter().zip(window.iter_mut())
    {
        *out = state.sysctls.get(if receive {
            NetSysctlKey::TcpRmem(slot)
        } else {
            NetSysctlKey::TcpWmem(slot)
        });
    }
    window
}

/// Which buffer defaults a new socket takes: Linux gives every socket the
/// generic `wmem_default`/`rmem_default` pair and then lets TCP replace them
/// with `tcp_wmem[1]`/`tcp_rmem[1]` when the protocol initialises. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BufPersonality { Generic, Tcp }

/// The `(sndbuf, rcvbuf)` a newly created socket starts with. # C: O(log N)
pub fn initial_bufs(namespace: &NetworkNamespaceRef, personality: BufPersonality) -> (i32, i32) {
    match personality {
        BufPersonality::Generic => (wmem_default() as i32, rmem_default() as i32),
        BufPersonality::Tcp => (
            clamp_buf(tcp_buf_window(namespace, false)[1]),
            clamp_buf(tcp_buf_window(namespace, true)[1]),
        ),
    }
}

fn clamp_buf(value: i64) -> i32 { value.clamp(0, i32::MAX as i64) as i32 }

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

/// `sysctl_mld_max_msf`: how many sources one IPv6 multicast source filter may
/// name. Global rather than per-namespace, as the reference keeps it.
static MLD_MAX_MSF: AtomicI64 =
    AtomicI64::new(crate::sock_opts::msfilter::DEFAULT_MLD_MAX_MSF);

pub const MLD_MAX_MSF_BOUNDS: (i64, i64) = (0, i32::MAX as i64);

/// # C: O(1)
pub fn mld_max_msf() -> i64 { MLD_MAX_MSF.load(Ordering::Acquire) }

/// # C: O(1)
pub fn set_mld_max_msf(value: i64) { MLD_MAX_MSF.store(value, Ordering::Release); }

/// The ceilings one multicast source-filter write is judged against. The v4
/// count ceiling is per-namespace and the v6 one is global, which is the split
/// the reference keeps. # C: O(log N)
pub fn msfilter_limits(ns: u64, v6: bool, wide: bool) -> crate::sock_opts::msfilter::Limits {
    use crate::sock_opts::msfilter;
    crate::sock_opts::msfilter::Limits {
        optmem_max: optmem_max_in(ns).unwrap_or(DEFAULT_OPTMEM_MAX),
        max_msf: if v6 { mld_max_msf() }
            else { value_in(ns, NetSysctlKey::Ipv4IgmpMaxMsf)
                .unwrap_or(msfilter::DEFAULT_IGMP_MAX_MSF) },
        numsrc_overflow: if wide { msfilter::MAX_NUMSRC_WIDE } else { msfilter::MAX_NUMSRC_NARROW },
    }
}

/// `net.ipv6.auto_flowlabels` in a live namespace: the flow-label policy a
/// socket that named none of its own inherits, and the one that overrides
/// every socket in both directions. # C: O(log N)
pub fn ipv6_auto_flowlabels_in(ns: u64) -> i64 {
    value_in(ns, NetSysctlKey::Ipv6AutoFlowLabels)
        .unwrap_or(crate::sock_opts::sol_ipv6::autolabel::DEFAULT_POLICY)
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
    fn the_generic_buffer_defaults_are_the_reference_kernels_and_are_writable() {
        let saved = (wmem_default(), rmem_default());
        set_wmem_default(DEFAULT_WMEM_DEFAULT as i64);
        set_rmem_default(DEFAULT_RMEM_DEFAULT as i64);
        // A datagram / AF_UNIX / packet socket starts far above the TCP send
        // buffer: 212992, not 16384.
        assert_eq!(wmem_default(), 212_992);
        assert_eq!(rmem_default(), 212_992);
        set_wmem_default(65_536);
        assert_eq!(wmem_default(), 65_536);
        set_wmem_default(saved.0 as i64);
        set_rmem_default(saved.1 as i64);
    }

    #[test]
    fn buffer_default_write_windows_floor_at_the_protocol_minimum() {
        assert_eq!(WMEM_DEFAULT_BOUNDS, (SOCK_MIN_SNDBUF as i64, i32::MAX as i64));
        assert_eq!(RMEM_DEFAULT_BOUNDS, (SOCK_MIN_RCVBUF as i64, i32::MAX as i64));
    }

    #[test]
    fn a_fresh_namespace_reports_the_compiled_tcp_buffer_windows() {
        let ns = namespace();
        assert_eq!(tcp_buf_window(&ns, false), DEFAULT_TCP_WMEM);
        assert_eq!(tcp_buf_window(&ns, true), DEFAULT_TCP_RMEM);
        // The send and receive middles differ — a TCP socket's initial receive
        // buffer is eight times its initial send buffer.
        assert_eq!(DEFAULT_TCP_WMEM[1], 16_384);
        assert_eq!(DEFAULT_TCP_RMEM[1], 131_072);
    }

    #[test]
    fn tcp_buffer_windows_are_isolated_per_namespace() {
        let first = namespace();
        let second = namespace();
        set_tcp_buf_window(&first, false, [1_024, 8_192, 1 << 20]).unwrap();
        assert_eq!(tcp_buf_window(&first, false), [1_024, 8_192, 1 << 20]);
        assert_eq!(tcp_buf_window(&second, false), DEFAULT_TCP_WMEM);
        // The receive window is a separate leaf and must not move with it.
        assert_eq!(tcp_buf_window(&first, true), DEFAULT_TCP_RMEM);
    }

    #[test]
    fn a_new_socket_takes_generic_defaults_unless_it_is_tcp() {
        let ns = namespace();
        assert_eq!(initial_bufs(&ns, BufPersonality::Generic),
            (wmem_default() as i32, rmem_default() as i32));
        assert_eq!(initial_bufs(&ns, BufPersonality::Tcp), (16_384, 131_072));
        // A namespace-local window write moves the TCP answer and leaves the
        // generic one alone.
        set_tcp_buf_window(&ns, false, [1_024, 40_000, 1 << 20]).unwrap();
        assert_eq!(initial_bufs(&ns, BufPersonality::Tcp).0, 40_000);
        assert_eq!(initial_bufs(&ns, BufPersonality::Generic).0, wmem_default() as i32);
    }

    #[test]
    fn invented_or_dead_ids_do_not_create_state() {
        assert_eq!(somaxconn_in(u64::MAX), None);
        assert!(set_somaxconn_in(u64::MAX, 1).is_err());
        assert!(crate::net_ns::state_by_id(u64::MAX).is_none());
    }
}
