// `bpf(2)` UAPI numbers and layouts.
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

/// `bpf_attr.file_flags` for `BPF_OBJ_GET`.
pub mod obj_get_flags {
    pub const RDONLY: u32 = 1 << 3;
    pub const WRONLY: u32 = 1 << 4;
    pub const MASK: u32 = RDONLY | WRONLY;
}

/// `sizeof(union bpf_attr)`. Largest member is the `BPF_PROG_LOAD`
/// anonymous struct: `keyring_id` at offset 164, `__aligned(8)`.
pub const ATTR_SIZE: usize = 168;

/// Extensible attributes are bounded to one page; larger values are
/// rejected with `E2BIG`.
pub const ATTR_MAX_USER_SIZE: usize = 4096;

/// `offsetofend(struct bpf_common_attr, log_true_size)`.
pub const COMMON_ATTR_SIZE: usize = 20;

pub mod off_common {
    pub const LOG_BUF: usize = 0;
    pub const LOG_SIZE: usize = 8;
    pub const LOG_LEVEL: usize = 12;
    pub const LOG_TRUE_SIZE: usize = 16;
}

#[path = "uapi/off.rs"]
pub mod off;

/// `enum bpf_stats_type`.
pub mod stats_type {
    pub const RUN_TIME: u32 = 0;
}

/// `BPF_F_TEST_*` flags on `attr.test.flags`.
pub mod test_flags {
    pub const RUN_ON_CPU:            u32 = 1 << 0;
    pub const XDP_LIVE_FRAMES:       u32 = 1 << 1;
    pub const SKB_CHECKSUM_COMPLETE: u32 = 1 << 2;
    /// The only flag an skb-context test run accepts.
    pub const SKB_MASK: u32 = SKB_CHECKSUM_COMPLETE;
}

/// `enum bpf_task_fd_type`.
pub mod fd_type {
    pub const RAW_TRACEPOINT: u32 = 0;
}

/// `BPF_OBJ_GET_NEXT_ID` refuses a starting id at or above `INT_MAX`
/// before consulting any capability.
pub const OBJECT_ID_LIMIT: u32 = i32::MAX as u32;

/// `ETH_HLEN` — the minimum `data_size_in` an skb-context test run accepts.
pub const ETH_HLEN: u32 = 14;

/// One page; the "silly large" ceiling on a user-supplied context size and
/// the budget the skb linear region is carved out of.
pub const PAGE_SIZE: u32 = 4096;
/// `NET_SKB_PAD + NET_IP_ALIGN` reserved ahead of the test frame.
pub const SKB_HEADROOM: u32 = 64 + 2;
/// `SKB_DATA_ALIGN(sizeof(struct skb_shared_info))` reserved behind it.
pub const SKB_TAILROOM: u32 = 320;
/// Largest linear region one page leaves after head and tail reservations.
pub const TEST_RUN_LINEAR_MAX: u32 = PAGE_SIZE - SKB_HEADROOM - SKB_TAILROOM;
/// `MAX_SKB_FRAGS` pages back everything past the linear region.
pub const MAX_SKB_FRAGS: u32 = 17;
/// Total input a test run can carry before the frag budget is exhausted.
pub const TEST_RUN_DATA_MAX: u32 = TEST_RUN_LINEAR_MAX + MAX_SKB_FRAGS * PAGE_SIZE;

/// `enum bpf_map_type`.
pub mod map_type {
    pub const UNSPEC:   u32 = 0;
    pub const HASH:     u32 = 1;
    pub const ARRAY:    u32 = 2;
    pub const LPM_TRIE: u32 = 11;
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
    pub const MAP_LOOKUP_ELEM:       u32 = 1;
    pub const KTIME_GET_NS:           u32 = 5;
    pub const GET_SMP_PROCESSOR_ID:   u32 = 8;
    pub const GET_CURRENT_PID_TGID:   u32 = 14;
    pub const GET_CURRENT_UID_GID:    u32 = 15;
    pub const GET_NUMA_NODE_ID:       u32 = 42;
    pub const GET_CURRENT_CGROUP_ID:  u32 = 80;
    pub const KTIME_GET_BOOT_NS:      u32 = 125;
    pub const KTIME_GET_COARSE_NS:    u32 = 160;
    pub const GET_RETVAL:             u32 = 186;
    pub const SET_RETVAL:             u32 = 187;
    pub const SKB_LOAD_BYTES:         u32 = 26;
}

/// `enum bpf_attach_type` values used by the implemented dispatch paths.
pub mod attach_type {
    pub const CGROUP_INET_INGRESS: u32 = 0;
    pub const CGROUP_INET_EGRESS:  u32 = 1;
    pub const CGROUP_DEVICE:       u32 = 6;
    pub const CGROUP_INET4_BIND:   u32 = 8;
    pub const CGROUP_INET6_BIND:   u32 = 9;
    pub const CGROUP_INET4_CONNECT: u32 = 10;
    pub const CGROUP_INET6_CONNECT: u32 = 11;
    pub const LSM_MAC:             u32 = 27;
    pub const TRACE_ITER:          u32 = 28;
    /// `__MAX_BPF_ATTACH_TYPE` in v7.2.0-rc4.
    pub const MAX:                 u32 = 62;
}

pub mod attach_flags {
    pub const ALLOW_OVERRIDE: u32 = 1 << 0;
    pub const ALLOW_MULTI:    u32 = 1 << 1;
    pub const REPLACE:        u32 = 1 << 2;
    pub const BEFORE:         u32 = 1 << 3;
    pub const AFTER:          u32 = 1 << 4;
    pub const ID:             u32 = 1 << 5;
    pub const PREORDER:       u32 = 1 << 6;
    pub const LINK:           u32 = 1 << 13;
    pub const BASE_MASK: u32 = ALLOW_OVERRIDE | ALLOW_MULTI | REPLACE | PREORDER;
    pub const ORDER_MASK: u32 = REPLACE | BEFORE | AFTER | ID | LINK;
    pub const CGROUP_MASK: u32 = BASE_MASK | ORDER_MASK;
    pub const CGROUP_LINK_MASK: u32 = ID | BEFORE | AFTER | PREORDER | LINK;
}

pub mod query_flags {
    pub const EFFECTIVE: u32 = 1 << 0;
}

pub mod btf_flags {
    pub const TOKEN_FD: u32 = 1 << 16;
}

pub mod log_flags {
    pub const LEVEL1: u32 = 1 << 0;
    pub const LEVEL2: u32 = 1 << 1;
    pub const STATS:  u32 = 1 << 2;
    pub const FIXED:  u32 = 1 << 3;
    pub const MASK: u32 = LEVEL1 | LEVEL2 | STATS | FIXED;
    pub const MAX_SIZE: u32 = u32::MAX >> 2;
}

/// `BPF_F_*` map-create flags.
pub mod map_flags {
    pub const NO_PREALLOC:   u32 = 1 << 0;
    pub const NO_COMMON_LRU: u32 = 1 << 1;
    pub const NUMA_NODE:     u32 = 1 << 2;
    pub const RDONLY:        u32 = 1 << 3;
    pub const WRONLY:        u32 = 1 << 4;
    pub const ZERO_SEED:     u32 = 1 << 6;
    pub const RDONLY_PROG:   u32 = 1 << 7;
    pub const WRONLY_PROG:   u32 = 1 << 8;
    pub const MMAPABLE:      u32 = 1 << 10;
    pub const TOKEN_FD:      u32 = 1 << 16;
    /// `BPF_F_ACCESS_MASK`.
    pub const ACCESS_MASK:   u32 = RDONLY | WRONLY | RDONLY_PROG | WRONLY_PROG;
    /// Hash-map creation flag mask.
    pub const HTAB_CREATE_MASK: u32 =
        NO_PREALLOC | NO_COMMON_LRU | NUMA_NODE | ACCESS_MASK | ZERO_SEED;
    pub const ARRAY_CREATE_MASK: u32 = NUMA_NODE | ACCESS_MASK | MMAPABLE;
    pub const LPM_CREATE_MASK: u32 = NO_PREALLOC | NUMA_NODE | ACCESS_MASK;
}

/// `src_reg` tags on `BPF_LD_IMM64` map relocations.
pub mod pseudo {
    pub const MAP_FD:    u8 = 1;
    pub const MAP_VALUE: u8 = 2;
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

/// Unprivileged instruction ceiling.
pub const MAXINSNS: u32 = 4096;
/// Privileged complexity ceiling.
pub const COMPLEXITY_LIMIT_INSNS: u32 = 1_000_000;
/// eBPF instruction width.
pub const INSN_SIZE: u32 = 8;
/// `NUMA_NO_NODE`.
pub const NUMA_NO_NODE: u32 = u32::MAX;
