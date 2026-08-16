// Kernel-side security class and permission enumeration.
//
// The kernel names classes and permissions by its OWN fixed identifiers; a
// loaded policy names them by its own symbol-table values, which need not
// agree (an older policy may lack a class the kernel knows, and may order
// permissions differently). `crate::mapping` builds the kernel-to-policy
// translation at load time from this table plus the policy's symbol tables.
//
// Class value is 1-based: the first entry is class 1, matching the reference
// enumeration where class 0 is "no class". Permission bit N is `1 << N` over
// the flattened permission-name sequence, so group order below is ABI and a
// reordering silently renames every permission after the change.

/// Permissions shared by every file-like and socket-like class.
pub const COMMON_FILE_SOCK_PERMS: &[&str] = &[
    "ioctl", "read", "write", "create", "getattr", "setattr", "lock",
    "relabelfrom", "relabelto", "append", "map",
];

/// File-class permissions beyond the file/socket shared set.
const FILE_EXTRA: &[&str] = &[
    "unlink", "link", "rename", "execute", "quotaon", "mounton",
    "audit_access", "open", "execmod", "watch", "watch_mount", "watch_sb",
    "watch_with_perm", "watch_reads", "watch_mountns",
];

/// Socket-class permissions beyond the file/socket shared set.
const SOCK_EXTRA: &[&str] = &[
    "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown",
    "recvfrom", "sendto", "name_bind",
];

/// Permissions shared by the System V IPC classes.
const IPC_PERMS: &[&str] = &[
    "create", "destroy", "getattr", "setattr", "read", "write", "associate",
    "unix_read", "unix_write",
];

/// Permissions of the first capability class, ordered by capability number.
const CAP_PERMS: &[&str] = &[
    "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill",
    "setgid", "setuid", "setpcap", "linux_immutable", "net_bind_service",
    "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
    "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
    "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time",
    "sys_tty_config", "mknod", "lease", "audit_write", "audit_control",
    "setfcap",
];

/// Permissions of the second capability class, continuing the numbering.
const CAP2_PERMS: &[&str] = &[
    "mac_override", "mac_admin", "syslog", "wake_alarm", "block_suspend",
    "audit_read", "perfmon", "bpf", "checkpoint_restore",
];

/// Permissions shared by every file-like class.
pub const COMMON_FILE_PERMS: &[&[&str]] = &[COMMON_FILE_SOCK_PERMS, FILE_EXTRA];
/// Permissions shared by every socket-like class.
pub const COMMON_SOCK_PERMS: &[&[&str]] = &[COMMON_FILE_SOCK_PERMS, SOCK_EXTRA];
/// Permissions shared by the System V IPC classes.
pub const COMMON_IPC_PERMS: &[&[&str]] = &[IPC_PERMS];
/// Permissions of the first capability class.
pub const COMMON_CAP_PERMS: &[&[&str]] = &[CAP_PERMS];
/// Permissions of the second capability class.
pub const COMMON_CAP2_PERMS: &[&[&str]] = &[CAP2_PERMS];

/// Declare one class's permission groups as a named constant.
///
/// Every group must be a named constant so the whole table lives in static
/// storage; an inline slice literal inside the class table would be a
/// temporary and would not outlive the initialiser.
macro_rules! perms {
    ($name:ident = $($group:expr),+ $(,)?) => {
        const $name: &[&[&str]] = &[$($group),+];
    };
}

perms!(P_SECURITY = &["compute_av", "compute_create", "compute_member",
    "check_context", "load_policy", "compute_relabel", "compute_user",
    "setenforce", "setbool", "setsecparam", "setcheckreqprot", "read_policy",
    "validate_trans"]);
perms!(P_PROCESS = &["fork", "transition", "sigchld", "sigkill", "sigstop",
    "signull", "signal", "ptrace", "getsched", "setsched", "getsession",
    "getpgid", "setpgid", "getcap", "setcap", "share", "getattr", "setexec",
    "setfscreate", "noatsecure", "siginh", "setrlimit", "rlimitinh",
    "dyntransition", "setcurrent", "execmem", "execstack", "execheap",
    "setkeycreate", "setsockcreate", "getrlimit"]);
perms!(P_PROCESS2 = &["nnp_transition", "nosuid_transition"]);
perms!(P_SYSTEM = &["ipc_info", "syslog_read", "syslog_mod", "syslog_console",
    "module_request", "module_load", "firmware_load", "kexec_image_load",
    "kexec_initramfs_load", "policy_load", "x509_certificate_load"]);
perms!(P_FILESYSTEM = &["mount", "remount", "unmount", "getattr",
    "relabelfrom", "relabelto", "associate", "quotamod", "quotaget", "watch"]);
perms!(P_FILE = COMMON_FILE_SOCK_PERMS, FILE_EXTRA,
    &["execute_no_trans", "entrypoint"]);
perms!(P_DIR = COMMON_FILE_SOCK_PERMS, FILE_EXTRA,
    &["add_name", "remove_name", "reparent", "search", "rmdir"]);
perms!(P_FD = &["use"]);
perms!(P_TCP_SOCKET = COMMON_FILE_SOCK_PERMS, SOCK_EXTRA,
    &["node_bind", "name_connect"]);
perms!(P_NODE_BIND_SOCKET = COMMON_FILE_SOCK_PERMS, SOCK_EXTRA, &["node_bind"]);
perms!(P_NODE = &["recvfrom", "sendto"]);
perms!(P_NETIF = &["ingress", "egress"]);
perms!(P_UNIX_STREAM_SOCKET = COMMON_FILE_SOCK_PERMS, SOCK_EXTRA,
    &["connectto"]);
perms!(P_MSG = &["send", "receive"]);
perms!(P_MSGQ = IPC_PERMS, &["enqueue"]);
perms!(P_SHM = IPC_PERMS, &["lock"]);
perms!(P_NLMSG_SOCKET = COMMON_FILE_SOCK_PERMS, SOCK_EXTRA,
    &["nlmsg_read", "nlmsg_write", "nlmsg"]);
perms!(P_NETLINK_AUDIT_SOCKET = COMMON_FILE_SOCK_PERMS, SOCK_EXTRA,
    &["nlmsg_read", "nlmsg_write", "nlmsg_relay", "nlmsg_readpriv",
      "nlmsg_tty_audit", "nlmsg"]);
perms!(P_ASSOCIATION = &["sendto", "recvfrom", "setcontext", "polmatch"]);
perms!(P_PACKET = &["send", "recv", "relabelto", "forward_in", "forward_out"]);
perms!(P_KEY = &["view", "read", "write", "search", "link", "setattr",
    "create"]);
perms!(P_MEMPROTECT = &["mmap_zero"]);
perms!(P_PEER = &["recv"]);
perms!(P_KERNEL_SERVICE = &["use_as_override", "create_files_as"]);
perms!(P_TUN_SOCKET = COMMON_FILE_SOCK_PERMS, SOCK_EXTRA, &["attach_queue"]);
perms!(P_BINDER = &["impersonate", "call", "set_context_mgr", "transfer"]);
perms!(P_SCTP_SOCKET = COMMON_FILE_SOCK_PERMS, SOCK_EXTRA,
    &["node_bind", "name_connect", "association"]);
perms!(P_INFINIBAND_PKEY = &["access"]);
perms!(P_INFINIBAND_ENDPORT = &["manage_subnet"]);
perms!(P_BPF = &["map_create", "map_read", "map_write", "prog_load",
    "prog_run", "map_create_as", "prog_load_as"]);
perms!(P_PERF_EVENT = &["open", "cpu", "kernel", "tracepoint", "read",
    "write"]);
perms!(P_IO_URING = &["override_creds", "sqpoll", "cmd", "allowed"]);
perms!(P_USER_NAMESPACE = &["create"]);

/// One security class: its policy-visible name and its permission groups.
pub struct ClassDef {
    /// Policy symbol-table name of the class.
    pub name: &'static str,
    /// Permission names in bit order, split into shared groups.
    pub perms: &'static [&'static [&'static str]],
}

const fn cls(name: &'static str, perms: &'static [&'static [&'static str]]) -> ClassDef {
    ClassDef { name, perms }
}

/// Every security class the kernel can name, in class-value order.
pub const SECCLASS_MAP: &[ClassDef] = &[
    cls("security", P_SECURITY),
    cls("process", P_PROCESS),
    cls("process2", P_PROCESS2),
    cls("system", P_SYSTEM),
    cls("capability", COMMON_CAP_PERMS),
    cls("filesystem", P_FILESYSTEM),
    cls("file", P_FILE),
    cls("dir", P_DIR),
    cls("fd", P_FD),
    cls("lnk_file", COMMON_FILE_PERMS),
    cls("chr_file", COMMON_FILE_PERMS),
    cls("blk_file", COMMON_FILE_PERMS),
    cls("sock_file", COMMON_FILE_PERMS),
    cls("fifo_file", COMMON_FILE_PERMS),
    cls("socket", COMMON_SOCK_PERMS),
    cls("tcp_socket", P_TCP_SOCKET),
    cls("udp_socket", P_NODE_BIND_SOCKET),
    cls("rawip_socket", P_NODE_BIND_SOCKET),
    cls("node", P_NODE),
    cls("netif", P_NETIF),
    cls("netlink_socket", COMMON_SOCK_PERMS),
    cls("packet_socket", COMMON_SOCK_PERMS),
    cls("key_socket", COMMON_SOCK_PERMS),
    cls("unix_stream_socket", P_UNIX_STREAM_SOCKET),
    cls("unix_dgram_socket", COMMON_SOCK_PERMS),
    cls("sem", COMMON_IPC_PERMS),
    cls("msg", P_MSG),
    cls("msgq", P_MSGQ),
    cls("shm", P_SHM),
    cls("ipc", COMMON_IPC_PERMS),
    cls("netlink_route_socket", P_NLMSG_SOCKET),
    cls("netlink_tcpdiag_socket", P_NLMSG_SOCKET),
    cls("netlink_nflog_socket", COMMON_SOCK_PERMS),
    cls("netlink_xfrm_socket", P_NLMSG_SOCKET),
    cls("netlink_selinux_socket", COMMON_SOCK_PERMS),
    cls("netlink_iscsi_socket", COMMON_SOCK_PERMS),
    cls("netlink_audit_socket", P_NETLINK_AUDIT_SOCKET),
    cls("netlink_fib_lookup_socket", COMMON_SOCK_PERMS),
    cls("netlink_connector_socket", COMMON_SOCK_PERMS),
    cls("netlink_netfilter_socket", COMMON_SOCK_PERMS),
    cls("netlink_dnrt_socket", COMMON_SOCK_PERMS),
    cls("association", P_ASSOCIATION),
    cls("netlink_kobject_uevent_socket", COMMON_SOCK_PERMS),
    cls("netlink_generic_socket", COMMON_SOCK_PERMS),
    cls("netlink_scsitransport_socket", COMMON_SOCK_PERMS),
    cls("netlink_rdma_socket", COMMON_SOCK_PERMS),
    cls("netlink_crypto_socket", COMMON_SOCK_PERMS),
    cls("appletalk_socket", COMMON_SOCK_PERMS),
    cls("packet", P_PACKET),
    cls("key", P_KEY),
    cls("memprotect", P_MEMPROTECT),
    cls("peer", P_PEER),
    cls("capability2", COMMON_CAP2_PERMS),
    cls("kernel_service", P_KERNEL_SERVICE),
    cls("tun_socket", P_TUN_SOCKET),
    cls("binder", P_BINDER),
    cls("cap_userns", COMMON_CAP_PERMS),
    cls("cap2_userns", COMMON_CAP2_PERMS),
    cls("sctp_socket", P_SCTP_SOCKET),
    cls("icmp_socket", P_NODE_BIND_SOCKET),
    cls("ax25_socket", COMMON_SOCK_PERMS),
    cls("ipx_socket", COMMON_SOCK_PERMS),
    cls("netrom_socket", COMMON_SOCK_PERMS),
    cls("atmpvc_socket", COMMON_SOCK_PERMS),
    cls("x25_socket", COMMON_SOCK_PERMS),
    cls("rose_socket", COMMON_SOCK_PERMS),
    cls("decnet_socket", COMMON_SOCK_PERMS),
    cls("atmsvc_socket", COMMON_SOCK_PERMS),
    cls("rds_socket", COMMON_SOCK_PERMS),
    cls("irda_socket", COMMON_SOCK_PERMS),
    cls("pppox_socket", COMMON_SOCK_PERMS),
    cls("llc_socket", COMMON_SOCK_PERMS),
    cls("can_socket", COMMON_SOCK_PERMS),
    cls("tipc_socket", COMMON_SOCK_PERMS),
    cls("bluetooth_socket", COMMON_SOCK_PERMS),
    cls("iucv_socket", COMMON_SOCK_PERMS),
    cls("rxrpc_socket", COMMON_SOCK_PERMS),
    cls("isdn_socket", COMMON_SOCK_PERMS),
    cls("phonet_socket", COMMON_SOCK_PERMS),
    cls("ieee802154_socket", COMMON_SOCK_PERMS),
    cls("caif_socket", COMMON_SOCK_PERMS),
    cls("alg_socket", COMMON_SOCK_PERMS),
    cls("nfc_socket", COMMON_SOCK_PERMS),
    cls("vsock_socket", COMMON_SOCK_PERMS),
    cls("kcm_socket", COMMON_SOCK_PERMS),
    cls("qipcrtr_socket", COMMON_SOCK_PERMS),
    cls("smc_socket", COMMON_SOCK_PERMS),
    cls("infiniband_pkey", P_INFINIBAND_PKEY),
    cls("infiniband_endport", P_INFINIBAND_ENDPORT),
    cls("bpf", P_BPF),
    cls("xdp_socket", COMMON_SOCK_PERMS),
    cls("mctp_socket", COMMON_SOCK_PERMS),
    cls("perf_event", P_PERF_EVENT),
    cls("anon_inode", COMMON_FILE_PERMS),
    cls("io_uring", P_IO_URING),
    cls("user_namespace", P_USER_NAMESPACE),
    cls("memfd_file", P_FILE),
];

/// Class definition for a 1-based kernel class value. # C: O(1)
pub fn class_def(class: u16) -> Option<&'static ClassDef> {
    if class == 0 { return None; }
    SECCLASS_MAP.get(class as usize - 1)
}

/// 1-based kernel class value for a policy class name. # C: O(classes)
pub fn class_by_name(name: &str) -> Option<u16> {
    SECCLASS_MAP.iter().position(|c| c.name == name).map(|i| i as u16 + 1)
}

/// Permission names of one class in bit order. # C: O(perms)
pub fn perm_names(def: &'static ClassDef) -> impl Iterator<Item = &'static str> {
    def.perms.iter().flat_map(|g| g.iter().copied())
}

/// Permission count of one class. # C: O(groups)
pub fn perm_count(def: &ClassDef) -> usize {
    def.perms.iter().map(|g| g.len()).sum()
}

/// Bit index of one named permission within its class. # C: O(perms)
pub fn perm_index(def: &'static ClassDef, name: &str) -> Option<u32> {
    perm_names(def).position(|p| p == name).map(|i| i as u32)
}

/// Access-vector bit of one named permission within its class. # C: O(perms)
pub fn perm_bit(class: u16, name: &str) -> Option<u32> {
    let def = class_def(class)?;
    let index = perm_index(def, name)?;
    if index >= u32::BITS { return None; }
    Some(1u32 << index)
}

#[cfg(test)]
#[path = "../tests/classmap.rs"]
mod tests;
