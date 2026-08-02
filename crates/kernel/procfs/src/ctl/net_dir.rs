// The `/proc/sys/net/` subtree — `net/core`, `net/ipv4` and their
// per-interface expansions.
//
// Split out of the tree manifest for the file-length cap; the split moves text,
// not policy. Every leaf binds to the same live network variable it did inline.

use super::*;
use Node::{Dir, File};

/// The children of `Dir("net", ...)`. # C: n/a
pub const NET_SYSCTLS: &[Node] = &[
        Dir("core", &[
            File("somaxconn",          NetInt(net::net_ns::NetSysctlKey::Somaxconn, Some((0, INT_MAX)))),
            File("optmem_max",         NetInt(net::net_ns::NetSysctlKey::OptmemMax, Some((0, INT_MAX)))),
            File("rmem_default",       NetGlobalIntHook(get_rmem_default, set_rmem_default,
                Some(net::sysctl::RMEM_DEFAULT_BOUNDS))),
            File("rmem_max",           NetGlobalIntHook(get_rmem_max, set_rmem_max,
                Some(net::sysctl::RMEM_MAX_BOUNDS))),
            File("wmem_default",       NetGlobalIntHook(get_wmem_default, set_wmem_default,
                Some(net::sysctl::WMEM_DEFAULT_BOUNDS))),
            File("wmem_max",           NetGlobalIntHook(get_wmem_max, set_wmem_max,
                Some(net::sysctl::WMEM_MAX_BOUNDS))),
            File("netdev_max_backlog", Const(b"1000\n")),
        ]),
        Dir("ipv4", &[
            File("ip_forward",         NetInt(net::net_ns::NetSysctlKey::Ipv4Conf(
                net::net_ns::Ipv4ConfDev::All, net::net_ns::Ipv4ConfKey::Forwarding), Some((0, 1)))),
            File("tcp_syncookies",     NetInt(net::net_ns::NetSysctlKey::TcpSyncookies, Some((0, 2)))),
            File("tcp_tw_reuse",       NetInt(net::net_ns::NetSysctlKey::TcpTwReuse, Some((0, 2)))),
            File("tcp_fin_timeout",    NetInt(net::net_ns::NetSysctlKey::TcpFinTimeout, Some((0, INT_MAX)))),
            File("tcp_keepalive_time", NetInt(net::net_ns::NetSysctlKey::TcpKeepaliveTime, Some((0, INT_MAX)))),
            File("tcp_wmem",           PerNetBufWindowHook(tcp_wmem, set_tcp_wmem,
                net::sysctl::TCP_MEM_BOUNDS)),
            File("tcp_rmem",           PerNetBufWindowHook(tcp_rmem, set_tcp_rmem,
                net::sysctl::TCP_MEM_BOUNDS)),
            File("ip_local_port_range", PerNetU16PairHook(local_port_range, set_local_port_range)),
            File("ip_unprivileged_port_start", PerNetIntHook(unprivileged_port_start,
                set_unprivileged_port_start, Some((0, 65_535)))),
            File("icmp_echo_ignore_all", NetInt(net::net_ns::NetSysctlKey::IcmpEchoIgnoreAll, Some((0, 1)))),
            // The group window that admits an ICMP datagram endpoint. The
            // compiled default `1 0` admits nobody; distributions open it at
            // boot so an echo-probe tool needs no capability.
            File("ping_group_range", PerNetGroupRangeHook(ping_group_range, set_ping_group_range)),
            File("ip_nonlocal_bind",   NetInt(net::net_ns::NetSysctlKey::Ipv4NonlocalBind, Some((0, 1)))),
            // The fast-open enable bits are a bit field, not a range: the
            // client and server halves are read independently, so no minimum
            // or maximum screens a write.
            File("tcp_fastopen",       NetInt(net::net_ns::NetSysctlKey::TcpFastopen, None)),
            // The keys the namespace's cookies are minted from. Owner-only:
            // anyone who can read them can forge a cookie for every listener
            // in the namespace.
            File("tcp_fastopen_key",   PerNetStrHook(tcp_fastopen_key, set_tcp_fastopen_key, true)),
        ]),
        Dir("ipv6", &[
            File("ip_nonlocal_bind",   NetInt(net::net_ns::NetSysctlKey::Ipv6NonlocalBind, Some((0, 1)))),
            Dir("conf", &[
                Dir("all",     &[ File("disable_ipv6", NetInt(net::net_ns::NetSysctlKey::Ipv6DisableAll, Some((0, 1)))) ]),
                Dir("default", &[ File("disable_ipv6", NetInt(net::net_ns::NetSysctlKey::Ipv6DisableDefault, Some((0, 1)))) ]),
            ]),
        ]),
];
