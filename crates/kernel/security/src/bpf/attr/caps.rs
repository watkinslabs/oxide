// Effective capability snapshot for one `bpf(2)` call, and the program-type
// capability classes the load path consults.


use super::super::uapi;

/// Effective capability snapshot for one `bpf(2)` call.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Caps { pub bpf: bool, pub sys_admin: bool, pub net_admin: bool, pub perfmon: bool }

impl Caps {
    /// `CAP_BPF` alone is sufficient; `CAP_SYS_ADMIN` is always an
    /// accepted superset. # C: O(1)
    pub fn bpf_capable(&self) -> bool { self.bpf || self.sys_admin }
    /// `CAP_PERFMON` alone is sufficient; `CAP_SYS_ADMIN` is always an
    /// accepted superset. # C: O(1)
    pub fn perfmon_capable(&self) -> bool { self.perfmon || self.sys_admin }
    /// Falls back to `CAP_NET_ADMIN || CAP_SYS_ADMIN` when there is no BPF
    /// token granting the capability. # C: O(1)
    pub fn net_admin_capable(&self) -> bool { self.net_admin || self.sys_admin }
}

/// Program types that require `CAP_NET_ADMIN` to load. # C: O(1)
pub fn is_net_admin_prog_type(t: u32) -> bool {
    use uapi::prog_type as p;
    matches!(t, p::SCHED_CLS | p::SCHED_ACT | p::XDP | p::LWT_IN | p::LWT_OUT
        | p::LWT_XMIT | p::LWT_SEG6LOCAL | p::SK_SKB | p::SK_MSG | p::FLOW_DISSECTOR
        | p::CGROUP_DEVICE | p::CGROUP_SOCK | p::CGROUP_SOCK_ADDR | p::CGROUP_SOCKOPT
        | p::CGROUP_SYSCTL | p::SOCK_OPS | p::EXT | p::NETFILTER)
}

/// Program types that require `CAP_PERFMON` to load. # C: O(1)
pub fn is_perfmon_prog_type(t: u32) -> bool {
    use uapi::prog_type as p;
    matches!(t, p::KPROBE | p::TRACEPOINT | p::PERF_EVENT | p::RAW_TRACEPOINT
        | p::RAW_TRACEPOINT_WRITABLE | p::TRACING | p::LSM | p::STRUCT_OPS | p::EXT)
}

/// The set of prog types actually indexed and dispatchable is a
/// build-time-selected subset; a type with no entry is `-EINVAL`.
///
/// The built-in set here is exactly the set that can be *executed*:
/// socket filters, the cgroup device and network hooks, and the LSM hooks
/// this kernel publishes as attach targets.
/// # C: O(1)
pub fn prog_type_supported(t: u32) -> bool {
    matches!(t, uapi::prog_type::SOCKET_FILTER | uapi::prog_type::CGROUP_DEVICE
        | uapi::prog_type::CGROUP_SKB | uapi::prog_type::CGROUP_SOCK_ADDR
        | uapi::prog_type::LSM)
}
