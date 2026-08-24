use syscall::errno::Errno;

use super::uapi;

/// Delegation masks owned by one bpffs mount and copied into each token it
/// creates. # C: O(1) storage
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BpfDelegation {
    pub allowed_cmds: u64,
    pub allowed_maps: u64,
    pub allowed_progs: u64,
    pub allowed_attachs: u64,
}

/// Parse bpffs's four colon-separated delegation values. Linux accepts enum
/// names and numeric masks; unknown names are refused rather than becoming a
/// silently broader token. # C: O(len(data))
pub fn parse_mount_delegation(data: &str) -> Result<BpfDelegation, Errno> {
    let mut out = BpfDelegation::default();
    for item in data.split(',') {
        let (key, value) = match item.split_once('=') { Some(v) => v, None => continue };
        let slot = match key {
            "delegate_cmds" => &mut out.allowed_cmds,
            "delegate_maps" => &mut out.allowed_maps,
            "delegate_progs" => &mut out.allowed_progs,
            "delegate_attachs" => &mut out.allowed_attachs,
            _ => continue,
        };
        for word in value.split(':') {
            *slot |= match word {
                "any" => u64::MAX,
                _ => parse_word(key, word).ok_or(Errno::Einval)?,
            };
        }
    }
    Ok(out)
}

const COMMANDS: &[(&str, u32)] = &[
    ("MAP_CREATE", 0),
    ("MAP_LOOKUP_ELEM", 1),
    ("MAP_UPDATE_ELEM", 2),
    ("MAP_DELETE_ELEM", 3),
    ("MAP_GET_NEXT_KEY", 4),
    ("PROG_LOAD", 5),
    ("OBJ_PIN", 6),
    ("OBJ_GET", 7),
    ("PROG_ATTACH", 8),
    ("PROG_DETACH", 9),
    ("PROG_TEST_RUN", 10),
    ("PROG_RUN", 10),
    ("PROG_GET_NEXT_ID", 11),
    ("MAP_GET_NEXT_ID", 12),
    ("PROG_GET_FD_BY_ID", 13),
    ("MAP_GET_FD_BY_ID", 14),
    ("OBJ_GET_INFO_BY_FD", 15),
    ("PROG_QUERY", 16),
    ("RAW_TRACEPOINT_OPEN", 17),
    ("BTF_LOAD", 18),
    ("BTF_GET_FD_BY_ID", 19),
    ("TASK_FD_QUERY", 20),
    ("MAP_LOOKUP_AND_DELETE_ELEM", 21),
    ("MAP_FREEZE", 22),
    ("BTF_GET_NEXT_ID", 23),
    ("MAP_LOOKUP_BATCH", 24),
    ("MAP_LOOKUP_AND_DELETE_BATCH", 25),
    ("MAP_UPDATE_BATCH", 26),
    ("MAP_DELETE_BATCH", 27),
    ("LINK_CREATE", 28),
    ("LINK_UPDATE", 29),
    ("LINK_GET_FD_BY_ID", 30),
    ("LINK_GET_NEXT_ID", 31),
    ("ENABLE_STATS", 32),
    ("ITER_CREATE", 33),
    ("LINK_DETACH", 34),
    ("PROG_BIND_MAP", 35),
    ("TOKEN_CREATE", 36),
    ("PROG_STREAM_READ_BY_FD", 37),
    ("PROG_ASSOC_STRUCT_OPS", 38),
];

const MAP_TYPES: &[(&str, u32)] = &[
    ("UNSPEC", 0),
    ("HASH", 1),
    ("ARRAY", 2),
    ("PROG_ARRAY", 3),
    ("PERF_EVENT_ARRAY", 4),
    ("PERCPU_HASH", 5),
    ("PERCPU_ARRAY", 6),
    ("STACK_TRACE", 7),
    ("CGROUP_ARRAY", 8),
    ("LRU_HASH", 9),
    ("LRU_PERCPU_HASH", 10),
    ("LPM_TRIE", 11),
    ("ARRAY_OF_MAPS", 12),
    ("HASH_OF_MAPS", 13),
    ("DEVMAP", 14),
    ("SOCKMAP", 15),
    ("CPUMAP", 16),
    ("XSKMAP", 17),
    ("SOCKHASH", 18),
    ("CGROUP_STORAGE_DEPRECATED", 19),
    ("CGROUP_STORAGE", 19),
    ("REUSEPORT_SOCKARRAY", 20),
    ("PERCPU_CGROUP_STORAGE_DEPRECATED", 21),
    ("PERCPU_CGROUP_STORAGE", 21),
    ("QUEUE", 22),
    ("STACK", 23),
    ("SK_STORAGE", 24),
    ("DEVMAP_HASH", 25),
    ("STRUCT_OPS", 26),
    ("RINGBUF", 27),
    ("INODE_STORAGE", 28),
    ("TASK_STORAGE", 29),
    ("BLOOM_FILTER", 30),
    ("USER_RINGBUF", 31),
    ("CGRP_STORAGE", 32),
    ("ARENA", 33),
    ("INSN_ARRAY", 34),
    ("RHASH", 35),
];

const PROG_TYPES: &[(&str, u32)] = &[
    ("UNSPEC", 0),
    ("SOCKET_FILTER", 1),
    ("KPROBE", 2),
    ("SCHED_CLS", 3),
    ("SCHED_ACT", 4),
    ("TRACEPOINT", 5),
    ("XDP", 6),
    ("PERF_EVENT", 7),
    ("CGROUP_SKB", 8),
    ("CGROUP_SOCK", 9),
    ("LWT_IN", 10),
    ("LWT_OUT", 11),
    ("LWT_XMIT", 12),
    ("SOCK_OPS", 13),
    ("SK_SKB", 14),
    ("CGROUP_DEVICE", 15),
    ("SK_MSG", 16),
    ("RAW_TRACEPOINT", 17),
    ("CGROUP_SOCK_ADDR", 18),
    ("LWT_SEG6LOCAL", 19),
    ("LIRC_MODE2", 20),
    ("SK_REUSEPORT", 21),
    ("FLOW_DISSECTOR", 22),
    ("CGROUP_SYSCTL", 23),
    ("RAW_TRACEPOINT_WRITABLE", 24),
    ("CGROUP_SOCKOPT", 25),
    ("TRACING", 26),
    ("STRUCT_OPS", 27),
    ("EXT", 28),
    ("LSM", 29),
    ("SK_LOOKUP", 30),
    ("SYSCALL", 31),
    ("NETFILTER", 32),
];

const ATTACH_TYPES: &[(&str, u32)] = &[
    ("CGROUP_INET_INGRESS", 0),
    ("CGROUP_INET_EGRESS", 1),
    ("CGROUP_INET_SOCK_CREATE", 2),
    ("CGROUP_SOCK_OPS", 3),
    ("SK_SKB_STREAM_PARSER", 4),
    ("SK_SKB_STREAM_VERDICT", 5),
    ("CGROUP_DEVICE", 6),
    ("SK_MSG_VERDICT", 7),
    ("CGROUP_INET4_BIND", 8),
    ("CGROUP_INET6_BIND", 9),
    ("CGROUP_INET4_CONNECT", 10),
    ("CGROUP_INET6_CONNECT", 11),
    ("CGROUP_INET4_POST_BIND", 12),
    ("CGROUP_INET6_POST_BIND", 13),
    ("CGROUP_UDP4_SENDMSG", 14),
    ("CGROUP_UDP6_SENDMSG", 15),
    ("LIRC_MODE2", 16),
    ("FLOW_DISSECTOR", 17),
    ("CGROUP_SYSCTL", 18),
    ("CGROUP_UDP4_RECVMSG", 19),
    ("CGROUP_UDP6_RECVMSG", 20),
    ("CGROUP_GETSOCKOPT", 21),
    ("CGROUP_SETSOCKOPT", 22),
    ("TRACE_RAW_TP", 23),
    ("TRACE_FENTRY", 24),
    ("TRACE_FEXIT", 25),
    ("MODIFY_RETURN", 26),
    ("LSM_MAC", 27),
    ("TRACE_ITER", 28),
    ("CGROUP_INET4_GETPEERNAME", 29),
    ("CGROUP_INET6_GETPEERNAME", 30),
    ("CGROUP_INET4_GETSOCKNAME", 31),
    ("CGROUP_INET6_GETSOCKNAME", 32),
    ("XDP_DEVMAP", 33),
    ("CGROUP_INET_SOCK_RELEASE", 34),
    ("XDP_CPUMAP", 35),
    ("SK_LOOKUP", 36),
    ("XDP", 37),
    ("SK_SKB_VERDICT", 38),
    ("SK_REUSEPORT_SELECT", 39),
    ("SK_REUSEPORT_SELECT_OR_MIGRATE", 40),
    ("PERF_EVENT", 41),
    ("TRACE_KPROBE_MULTI", 42),
    ("LSM_CGROUP", 43),
    ("STRUCT_OPS", 44),
    ("NETFILTER", 45),
    ("TCX_INGRESS", 46),
    ("TCX_EGRESS", 47),
    ("TRACE_UPROBE_MULTI", 48),
    ("CGROUP_UNIX_CONNECT", 49),
    ("CGROUP_UNIX_SENDMSG", 50),
    ("CGROUP_UNIX_RECVMSG", 51),
    ("CGROUP_UNIX_GETPEERNAME", 52),
    ("CGROUP_UNIX_GETSOCKNAME", 53),
    ("NETKIT_PRIMARY", 54),
    ("NETKIT_PEER", 55),
    ("TRACE_KPROBE_SESSION", 56),
    ("TRACE_UPROBE_SESSION", 57),
    ("TRACE_FSESSION", 58),
    ("TRACE_FENTRY_MULTI", 59),
    ("TRACE_FEXIT_MULTI", 60),
    ("TRACE_FSESSION_MULTI", 61),
];

fn parse_word(key: &str, word: &str) -> Option<u64> {
    if let Some(v) = word.strip_prefix("0x") {
        return u64::from_str_radix(v, 16).ok();
    }
    if word.bytes().all(|b| b.is_ascii_digit()) {
        return word.parse().ok();
    }
    let table = match key {
        "delegate_cmds" => COMMANDS,
        "delegate_maps" => MAP_TYPES,
        "delegate_progs" => PROG_TYPES,
        "delegate_attachs" => ATTACH_TYPES,
        _ => return None,
    };
    table.iter().find(|(name, _)| *name == word).map(|(_, value)| 1u64 << value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_numeric_masks_accumulate_per_mount_field() {
        let got = parse_mount_delegation(
            "delegate_cmds=MAP_CREATE:0x20,delegate_maps=HASH:ARRAY,delegate_progs=SOCKET_FILTER,delegate_attachs=any",
        ).unwrap();
        assert_eq!(got.allowed_cmds, (1u64 << uapi::cmd::MAP_CREATE) | 0x20);
        assert_eq!(got.allowed_maps, (1u64 << uapi::map_type::HASH) | (1u64 << uapi::map_type::ARRAY));
        assert_eq!(got.allowed_progs, 1u64 << uapi::prog_type::SOCKET_FILTER);
        assert_eq!(got.allowed_attachs, u64::MAX);
    }

    #[test]
    fn unknown_names_and_malformed_values_are_refused() {
        assert_eq!(parse_mount_delegation("delegate_cmds=NO_SUCH_COMMAND"), Err(Errno::Einval));
        assert_eq!(parse_mount_delegation("delegate_maps=0x"), Err(Errno::Einval));
    }
}
