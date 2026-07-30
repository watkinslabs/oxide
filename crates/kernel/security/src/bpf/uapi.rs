// `bpf(2)` UAPI numbers. Source: linux-master v7.2.0-rc4
// `include/uapi/linux/bpf.h` — `enum bpf_cmd`, `union bpf_attr`,
// `enum bpf_map_type`, `enum bpf_prog_type`, `enum bpf_attach_type`
// and the `BPF_F_*` flag enums.
//
// Numbers only. Every policy decision lives in `attr.rs` / `prog.rs` /
// `map.rs` per `docs/53`.

/// `enum bpf_cmd`.
pub mod cmd {
    pub const MAP_CREATE:                  u32 = 0;
    pub const MAP_LOOKUP_ELEM:             u32 = 1;
    pub const MAP_UPDATE_ELEM:             u32 = 2;
    pub const MAP_DELETE_ELEM:             u32 = 3;
    pub const MAP_GET_NEXT_KEY:            u32 = 4;
    pub const PROG_LOAD:                   u32 = 5;
    pub const OBJ_PIN:                     u32 = 6;
    pub const OBJ_GET:                     u32 = 7;
    pub const PROG_ATTACH:                 u32 = 8;
    pub const PROG_DETACH:                 u32 = 9;
    pub const PROG_TEST_RUN:               u32 = 10;
    pub const PROG_GET_NEXT_ID:            u32 = 11;
    pub const MAP_GET_NEXT_ID:             u32 = 12;
    pub const PROG_GET_FD_BY_ID:           u32 = 13;
    pub const MAP_GET_FD_BY_ID:            u32 = 14;
    pub const OBJ_GET_INFO_BY_FD:          u32 = 15;
    pub const PROG_QUERY:                  u32 = 16;
    pub const RAW_TRACEPOINT_OPEN:         u32 = 17;
    pub const BTF_LOAD:                    u32 = 18;
    pub const BTF_GET_FD_BY_ID:            u32 = 19;
    pub const TASK_FD_QUERY:               u32 = 20;
    pub const MAP_LOOKUP_AND_DELETE_ELEM:  u32 = 21;
    pub const MAP_FREEZE:                  u32 = 22;
    pub const BTF_GET_NEXT_ID:             u32 = 23;
    pub const MAP_LOOKUP_BATCH:            u32 = 24;
    pub const MAP_LOOKUP_AND_DELETE_BATCH: u32 = 25;
    pub const MAP_UPDATE_BATCH:            u32 = 26;
    pub const MAP_DELETE_BATCH:            u32 = 27;
    pub const LINK_CREATE:                 u32 = 28;
    pub const LINK_UPDATE:                 u32 = 29;
    pub const LINK_GET_FD_BY_ID:           u32 = 30;
    pub const LINK_GET_NEXT_ID:            u32 = 31;
    pub const ENABLE_STATS:                u32 = 32;
    pub const ITER_CREATE:                 u32 = 33;
    pub const LINK_DETACH:                 u32 = 34;
    pub const PROG_BIND_MAP:               u32 = 35;
    pub const TOKEN_CREATE:                u32 = 36;
    pub const PROG_STREAM_READ_BY_FD:      u32 = 37;
    pub const PROG_ASSOC_STRUCT_OPS:       u32 = 38;
    /// `__MAX_BPF_CMD`.
    pub const MAX:                         u32 = 39;
    /// `BPF_COMMON_ATTRS` — cmd bit selecting the 5-argument
    /// (`uattr_common`, `size_common`) log-attr form.
    pub const COMMON_ATTRS:                u32 = 1 << 16;
}

/// `sizeof(union bpf_attr)`. Largest member is the `BPF_PROG_LOAD`
/// anonymous struct: `keyring_id` at offset 164, `__aligned(8)`.
pub const ATTR_SIZE: usize = 168;

/// `bpf_check_uarg_tail_zero()`'s "silly large" ceiling is `PAGE_SIZE`
/// (kernel/bpf/syscall.c) — a larger `size` is `-E2BIG` outright.
pub const ATTR_MAX_USER_SIZE: usize = 4096;

/// `offsetofend(struct bpf_common_attr, log_true_size)`.
pub const COMMON_ATTR_SIZE: usize = 24;

/// `union bpf_attr` field offsets, grouped by the command that owns
/// the anonymous struct. `LAST_END` is
/// `offsetofend(union bpf_attr, <CMD>_LAST_FIELD)` — the start of the
/// region `CHECK_ATTR(CMD)` requires to be all-zero.
pub mod off {
    /// `BPF_MAP_CREATE`; `BPF_MAP_CREATE_LAST_FIELD excl_prog_hash_size`.
    pub mod map_create {
        pub const MAP_TYPE:    usize = 0;
        pub const KEY_SIZE:    usize = 4;
        pub const VALUE_SIZE:  usize = 8;
        pub const MAX_ENTRIES: usize = 12;
        pub const MAP_FLAGS:   usize = 16;
        pub const NUMA_NODE:   usize = 24;
        pub const MAP_EXTRA:   usize = 64;
        pub const LAST_END:    usize = 92;
    }
    /// `BPF_MAP_*_ELEM` / `BPF_MAP_FREEZE`. `LAST_FIELD` differs per
    /// command, so each gets its own `*_LAST_END`.
    pub mod map_elem {
        pub const MAP_FD:   usize = 0;
        pub const KEY:      usize = 8;
        pub const VALUE:    usize = 16;
        pub const NEXT_KEY: usize = 16;
        pub const FLAGS:    usize = 24;
        /// `BPF_MAP_LOOKUP_ELEM_LAST_FIELD flags`, ditto UPDATE and
        /// `BPF_MAP_LOOKUP_AND_DELETE_ELEM_LAST_FIELD flags`.
        pub const FLAGS_LAST_END:    usize = 32;
        /// `BPF_MAP_DELETE_ELEM_LAST_FIELD key`.
        pub const KEY_LAST_END:      usize = 16;
        /// `BPF_MAP_GET_NEXT_KEY_LAST_FIELD next_key`.
        pub const NEXT_KEY_LAST_END: usize = 24;
        /// `BPF_MAP_FREEZE_LAST_FIELD map_fd`.
        pub const MAP_FD_LAST_END:   usize = 4;
    }
    /// `BPF_PROG_LOAD`; `BPF_PROG_LOAD_LAST_FIELD keyring_id` ends the
    /// union, so `CHECK_ATTR(BPF_PROG_LOAD)` checks an empty region.
    pub mod prog_load {
        pub const PROG_TYPE:  usize = 0;
        pub const INSN_CNT:   usize = 4;
        pub const INSNS:      usize = 8;
        pub const LICENSE:    usize = 16;
        pub const PROG_FLAGS: usize = 44;
        pub const EXPECTED_ATTACH_TYPE: usize = 68;
        pub const LAST_END:   usize = 168;
    }
    /// `BPF_PROG_ATTACH` / `BPF_PROG_DETACH`;
    /// `LAST_FIELD expected_revision`.
    pub mod prog_attach {
        pub const TARGET_FD:         usize = 0;
        pub const ATTACH_BPF_FD:     usize = 4;
        pub const ATTACH_TYPE:       usize = 8;
        pub const ATTACH_FLAGS:      usize = 12;
        pub const REPLACE_BPF_FD:    usize = 16;
        pub const RELATIVE_FD:       usize = 20;
        pub const EXPECTED_REVISION: usize = 24;
        pub const LAST_END:          usize = 32;
    }
    /// `BPF_PROG_QUERY`; `LAST_FIELD query.revision`.
    pub mod prog_query {
        pub const TARGET_FD:         usize = 0;
        pub const ATTACH_TYPE:       usize = 4;
        pub const QUERY_FLAGS:       usize = 8;
        pub const ATTACH_FLAGS:      usize = 12;
        pub const PROG_IDS:          usize = 16;
        pub const PROG_CNT:          usize = 24;
        pub const PROG_ATTACH_FLAGS: usize = 32;
        pub const LINK_IDS:          usize = 40;
        pub const LINK_ATTACH_FLAGS: usize = 48;
        pub const REVISION:          usize = 56;
        pub const LAST_END:          usize = 64;
    }
    /// `BPF_PROG_GET_FD_BY_ID`; `LAST_FIELD prog_id`.
    pub mod prog_get_fd_by_id {
        pub const PROG_ID:  usize = 0;
        pub const LAST_END: usize = 4;
    }
    /// `BPF_LINK_CREATE`;
    /// `LAST_FIELD link_create.uprobe_multi.path_fd` (ends at 64).
    pub mod link_create {
        pub const PROG_FD:       usize = 0;
        pub const TARGET_FD:     usize = 4;
        pub const ATTACH_TYPE:   usize = 8;
        pub const FLAGS:         usize = 12;
        pub const TARGET_BTF_ID: usize = 16;
        pub const LAST_END:      usize = 64;
    }
}

/// `enum bpf_map_type`.
pub mod map_type {
    pub const UNSPEC: u32 = 0;
    pub const HASH:   u32 = 1;
    pub const ARRAY:  u32 = 2;
    /// `__MAX_BPF_MAP_TYPE` in v7.2.0-rc4.
    pub const MAX:    u32 = 46;
}

/// `enum bpf_prog_type`.
pub mod prog_type {
    pub const UNSPEC:              u32 = 0;
    pub const SOCKET_FILTER:       u32 = 1;
    pub const KPROBE:              u32 = 2;
    pub const SCHED_CLS:           u32 = 3;
    pub const SCHED_ACT:           u32 = 4;
    pub const TRACEPOINT:          u32 = 5;
    pub const XDP:                 u32 = 6;
    pub const PERF_EVENT:          u32 = 7;
    pub const CGROUP_SKB:          u32 = 8;
    pub const CGROUP_SOCK:         u32 = 9;
    pub const LWT_IN:              u32 = 10;
    pub const LWT_OUT:             u32 = 11;
    pub const LWT_XMIT:            u32 = 12;
    pub const SOCK_OPS:            u32 = 13;
    pub const SK_SKB:              u32 = 14;
    pub const CGROUP_DEVICE:       u32 = 15;
    pub const SK_MSG:              u32 = 16;
    pub const RAW_TRACEPOINT:      u32 = 17;
    pub const CGROUP_SOCK_ADDR:    u32 = 18;
    pub const LWT_SEG6LOCAL:       u32 = 19;
    pub const LIRC_MODE2:          u32 = 20;
    pub const SK_REUSEPORT:        u32 = 21;
    pub const FLOW_DISSECTOR:      u32 = 22;
    pub const CGROUP_SYSCTL:       u32 = 23;
    pub const RAW_TRACEPOINT_WRITABLE: u32 = 24;
    pub const CGROUP_SOCKOPT:      u32 = 25;
    pub const TRACING:             u32 = 26;
    pub const STRUCT_OPS:          u32 = 27;
    pub const EXT:                 u32 = 28;
    pub const LSM:                 u32 = 29;
    pub const SK_LOOKUP:           u32 = 30;
    pub const SYSCALL:             u32 = 31;
    pub const NETFILTER:           u32 = 32;
    /// `__MAX_BPF_PROG_TYPE`.
    pub const MAX:                 u32 = 33;
}

/// `enum bpf_func_id` values implemented by the cgroup-device runner.
pub mod func_id {
    pub const KTIME_GET_NS:           u32 = 5;
    pub const GET_SMP_PROCESSOR_ID:   u32 = 8;
    pub const GET_CURRENT_PID_TGID:   u32 = 14;
    pub const GET_CURRENT_UID_GID:    u32 = 15;
    pub const GET_NUMA_NODE_ID:       u32 = 42;
    pub const GET_CURRENT_CGROUP_ID:  u32 = 80;
    pub const KTIME_GET_BOOT_NS:      u32 = 125;
}

/// `enum bpf_attach_type` values used by the implemented dispatch paths.
pub mod attach_type {
    pub const CGROUP_INET_INGRESS: u32 = 0;
    pub const CGROUP_INET_EGRESS:  u32 = 1;
    pub const CGROUP_DEVICE:       u32 = 6;
    pub const LSM_MAC:             u32 = 27;
    /// `__MAX_BPF_ATTACH_TYPE` in v7.2.0-rc4.
    pub const MAX:                 u32 = 62;
}

pub mod attach_flags {
    pub const ALLOW_OVERRIDE: u32 = 1 << 0;
    pub const ALLOW_MULTI:    u32 = 1 << 1;
    pub const REPLACE:        u32 = 1 << 2;
}

pub mod query_flags {
    pub const EFFECTIVE: u32 = 1 << 0;
}

/// `BPF_F_*` map-create flags (`include/uapi/linux/bpf.h`).
pub mod map_flags {
    pub const NO_PREALLOC:   u32 = 1 << 0;
    pub const NO_COMMON_LRU: u32 = 1 << 1;
    pub const NUMA_NODE:     u32 = 1 << 2;
    pub const RDONLY:        u32 = 1 << 3;
    pub const WRONLY:        u32 = 1 << 4;
    pub const ZERO_SEED:     u32 = 1 << 6;
    pub const RDONLY_PROG:   u32 = 1 << 7;
    pub const WRONLY_PROG:   u32 = 1 << 8;
    pub const TOKEN_FD:      u32 = 1 << 16;
    /// `BPF_F_ACCESS_MASK`.
    pub const ACCESS_MASK:   u32 = RDONLY | WRONLY | RDONLY_PROG | WRONLY_PROG;
    /// `HTAB_CREATE_FLAG_MASK` (kernel/bpf/hashtab.c).
    pub const HTAB_CREATE_MASK: u32 =
        NO_PREALLOC | NO_COMMON_LRU | NUMA_NODE | ACCESS_MASK | ZERO_SEED;
}

/// map element-op `attr.flags` values (the `BPF_ANY` enum).
pub mod elem_flags {
    pub const ANY:      u64 = 0;
    pub const NOEXIST:  u64 = 1;
    pub const EXIST:    u64 = 2;
    pub const F_LOCK:   u64 = 4;
    pub const F_CPU:    u64 = 8;
    pub const F_ALL_CPUS: u64 = 16;
}

/// `BPF_F_*` prog-load flags accepted by `bpf_prog_load()`'s mask test.
pub mod prog_flags {
    pub const STRICT_ALIGNMENT:   u32 = 1 << 0;
    pub const ANY_ALIGNMENT:      u32 = 1 << 1;
    pub const TEST_RND_HI32:      u32 = 1 << 2;
    pub const TEST_STATE_FREQ:    u32 = 1 << 3;
    pub const SLEEPABLE:          u32 = 1 << 4;
    pub const XDP_HAS_FRAGS:      u32 = 1 << 5;
    pub const XDP_DEV_BOUND_ONLY: u32 = 1 << 6;
    pub const TEST_REG_INVARIANTS: u32 = 1 << 7;
    pub const TOKEN_FD:           u32 = 1 << 16;
    /// The exact mask `bpf_prog_load()` rejects outside of.
    pub const LOAD_MASK: u32 = STRICT_ALIGNMENT | ANY_ALIGNMENT | TEST_STATE_FREQ
        | SLEEPABLE | TEST_RND_HI32 | XDP_HAS_FRAGS | XDP_DEV_BOUND_ONLY
        | TEST_REG_INVARIANTS | TOKEN_FD;
}

/// `BPF_MAXINSNS` (include/linux/filter.h) — the unprivileged ceiling.
pub const MAXINSNS: u32 = 4096;
/// `BPF_COMPLEXITY_LIMIT_INSNS` (include/linux/bpf.h) — the
/// `bpf_capable()` ceiling.
pub const COMPLEXITY_LIMIT_INSNS: u32 = 1_000_000;
/// eBPF instruction width.
pub const INSN_SIZE: u32 = 8;
/// `NUMA_NO_NODE`.
pub const NUMA_NO_NODE: u32 = u32::MAX;
