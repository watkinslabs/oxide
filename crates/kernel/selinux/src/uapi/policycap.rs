// Policy capabilities: per-policy opt-ins that change kernel behaviour. The
// policy image carries them as a bitmap; `selinuxfs` publishes one file per
// name under `policy_capabilities/`.

/// Peer, netif and node checks on network traffic.
pub const POLICYDB_CAP_NETPEER: u32 = 0;
/// The `open` permission is checked on file opens.
pub const POLICYDB_CAP_OPENPERM: u32 = 1;
/// Sockets get their specific class rather than the generic one.
pub const POLICYDB_CAP_EXTSOCKCLASS: u32 = 2;
/// Network checks run even when no network policy is loaded.
pub const POLICYDB_CAP_ALWAYSNETWORK: u32 = 3;
/// Cgroup files accept a security label.
pub const POLICYDB_CAP_CGROUPSECLABEL: u32 = 4;
/// No-new-privs and nosuid mounts permit a labelled transition.
pub const POLICYDB_CAP_NNP_NOSUID_TRANSITION: u32 = 5;
/// Symlinks in genfs-labelled filesystems get their own label.
pub const POLICYDB_CAP_GENFS_SECLABEL_SYMLINKS: u32 = 6;
/// Ioctl permission checks skip the close-on-exec commands.
pub const POLICYDB_CAP_IOCTL_SKIP_CLOEXEC: u32 = 7;
/// Userspace object managers use the policy's initial contexts.
pub const POLICYDB_CAP_USERSPACE_INITIAL_CONTEXT: u32 = 8;
/// Netlink messages are checked with extended permissions.
pub const POLICYDB_CAP_NETLINK_XPERM: u32 = 9;
/// Wildcard network-interface contexts are honoured.
pub const POLICYDB_CAP_NETIF_WILDCARD: u32 = 10;
/// Wildcard genfscon paths are honoured.
pub const POLICYDB_CAP_GENFS_SECLABEL_WILDCARD: u32 = 11;
/// FunctionFS files accept a security label.
pub const POLICYDB_CAP_FUNCTIONFS_SECLABEL: u32 = 12;
/// Anonymous memory files get their own class.
pub const POLICYDB_CAP_MEMFD_CLASS: u32 = 13;
/// BPF token permissions are checked.
pub const POLICYDB_CAP_BPF_TOKEN_PERMS: u32 = 14;

/// Number of defined policy capabilities.
pub const POLICYDB_CAP_MAX: u32 = 15;

/// Capability names in bit order, as published by `selinuxfs`.
pub const POLICYCAP_NAMES: [&str; POLICYDB_CAP_MAX as usize] = [
    "network_peer_controls",
    "open_perms",
    "extended_socket_class",
    "always_check_network",
    "cgroup_seclabel",
    "nnp_nosuid_transition",
    "genfs_seclabel_symlinks",
    "ioctl_skip_cloexec",
    "userspace_initial_context",
    "netlink_xperm",
    "netif_wildcard",
    "genfs_seclabel_wildcard",
    "functionfs_seclabel",
    "memfd_class",
    "bpf_token_perms",
];

/// Name of one policy capability bit. # C: O(1)
pub fn policycap_name(bit: u32) -> Option<&'static str> {
    POLICYCAP_NAMES.get(bit as usize).copied()
}
