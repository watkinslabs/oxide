// `union bpf_attr` field offsets, grouped by the command that owns the
// anonymous struct. `LAST_END` is
// `offsetofend(union bpf_attr, <CMD>_LAST_FIELD)` — the start of the
// region `CHECK_ATTR(CMD)` requires to be all-zero.

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
    /// In-kernel BTF type id the program attaches to.
    pub const ATTACH_BTF_ID: usize = 108;
    /// Either the BTF object holding that type id, or a program to attach to;
    /// the two share one slot.
    pub const ATTACH_BTF_OBJ_FD: usize = 112;
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
/// `BPF_MAP_GET_FD_BY_ID`; `LAST_FIELD map_id`.
pub mod map_get_fd_by_id {
    pub const MAP_ID:   usize = 0;
    pub const LAST_END: usize = 4;
}
/// `BPF_OBJ_PIN`; pathname, descriptor, and file flags.
pub mod obj_pin {
    pub const BPF_FD:     usize = 0;
    pub const PATHNAME:   usize = 8;
    pub const FILE_FLAGS: usize = 16;
    pub const LAST_END:   usize = 20;
}
/// `BPF_OBJ_GET`; pathname and file flags.
pub mod obj_get {
    pub const PATHNAME:   usize = 0;
    pub const FILE_FLAGS: usize = 8;
    pub const LAST_END:   usize = 12;
}
/// `BPF_PROG_BIND_MAP`; flags ends the 12-byte command payload.
pub mod prog_bind_map {
    pub const PROG_FD:  usize = 0;
    pub const MAP_FD:   usize = 4;
    pub const FLAGS:    usize = 8;
    pub const LAST_END: usize = 12;
}
pub mod btf_load {
    pub const DATA:          usize = 0;
    pub const LOG_BUF:       usize = 8;
    pub const DATA_SIZE:     usize = 16;
    pub const LOG_SIZE:      usize = 20;
    pub const LOG_LEVEL:     usize = 24;
    pub const LOG_TRUE_SIZE: usize = 28;
    pub const FLAGS:         usize = 32;
    pub const TOKEN_FD:      usize = 36;
    pub const LAST_END:      usize = 40;
}
pub mod object_id {
    pub const START_ID: usize = 0;
    pub const NEXT_ID:  usize = 4;
    pub const FLAGS:    usize = 8;
    pub const TOKEN_FD: usize = 12;
    pub const NEXT_LAST_END: usize = 8;
    pub const FD_LAST_END:   usize = 16;
}
pub mod object_info {
    pub const FD:       usize = 0;
    pub const INFO_LEN: usize = 4;
    pub const INFO:     usize = 8;
    pub const LAST_END: usize = 16;
}
/// `BPF_LINK_CREATE`;
/// `LAST_FIELD link_create.uprobe_multi.path_fd` (ends at 64).
pub mod link_create {
    pub const PROG_FD:                 usize = 0;
    pub const TARGET_FD:               usize = 4;
    pub const ATTACH_TYPE:             usize = 8;
    pub const FLAGS:                   usize = 12;
    pub const TARGET_BTF_ID:           usize = 16;
    pub const CGROUP_RELATIVE_FD:      usize = 16;
    pub const CGROUP_EXPECTED_REVISION: usize = 24;
    pub const LAST_END:                usize = 64;
}
/// `BPF_PROG_TEST_RUN`; `LAST_FIELD test.batch_size`.
pub mod test {
    pub const PROG_FD:       usize = 0;
    pub const RETVAL:        usize = 4;
    pub const DATA_SIZE_IN:  usize = 8;
    pub const DATA_SIZE_OUT: usize = 12;
    pub const DATA_IN:       usize = 16;
    pub const DATA_OUT:      usize = 24;
    pub const REPEAT:        usize = 32;
    pub const DURATION:      usize = 36;
    pub const CTX_SIZE_IN:   usize = 40;
    pub const CTX_SIZE_OUT:  usize = 44;
    pub const CTX_IN:        usize = 48;
    pub const CTX_OUT:       usize = 56;
    pub const FLAGS:         usize = 64;
    pub const CPU:           usize = 68;
    pub const BATCH_SIZE:    usize = 72;
    pub const LAST_END:      usize = 76;
}
/// `BPF_LINK_GET_FD_BY_ID`; `LAST_FIELD link_id`.
pub mod link_get_fd_by_id {
    pub const LINK_ID:  usize = 0;
    pub const LAST_END: usize = 4;
}
/// `BPF_LINK_DETACH`; `LAST_FIELD link_detach.link_fd`.
pub mod link_detach {
    pub const LINK_FD:  usize = 0;
    pub const LAST_END: usize = 4;
}
/// `BPF_LINK_UPDATE`; `LAST_FIELD link_update.old_prog_fd`.
pub mod link_update {
    pub const LINK_FD:     usize = 0;
    pub const NEW_PROG_FD: usize = 4;
    pub const FLAGS:       usize = 8;
    pub const OLD_PROG_FD: usize = 12;
    pub const LAST_END:    usize = 16;
}
/// `BPF_ENABLE_STATS`; `LAST_FIELD enable_stats.type`.
pub mod enable_stats {
    pub const TYPE:     usize = 0;
    pub const LAST_END: usize = 4;
}
/// The four `BPF_MAP_*_BATCH` commands; `LAST_FIELD batch.flags`.
pub mod batch {
    pub const IN_BATCH:   usize = 0;
    pub const OUT_BATCH:  usize = 8;
    pub const KEYS:       usize = 16;
    pub const VALUES:     usize = 24;
    pub const COUNT:      usize = 32;
    pub const MAP_FD:     usize = 36;
    pub const ELEM_FLAGS: usize = 40;
    pub const FLAGS:      usize = 48;
    pub const LAST_END:   usize = 56;
}
/// `BPF_ITER_CREATE`; `LAST_FIELD iter_create.flags`.
pub mod iter_create {
    pub const LINK_FD:  usize = 0;
    pub const FLAGS:    usize = 4;
    pub const LAST_END: usize = 8;
}
/// `BPF_TASK_FD_QUERY`; `LAST_FIELD task_fd_query.probe_addr`.
pub mod task_fd_query {
    pub const PID:          usize = 0;
    pub const FD:           usize = 4;
    pub const FLAGS:        usize = 8;
    pub const BUF_LEN:      usize = 12;
    pub const BUF:          usize = 16;
    pub const PROG_ID:      usize = 24;
    pub const FD_TYPE:      usize = 28;
    pub const PROBE_OFFSET: usize = 32;
    pub const PROBE_ADDR:   usize = 40;
    pub const LAST_END:     usize = 48;
}
/// `BPF_RAW_TRACEPOINT_OPEN`; `LAST_FIELD raw_tracepoint.cookie`.
/// `prog_fd` ends at 12 and `cookie` is 8-aligned, so 12..16 is padding
/// that the `CHECK_ATTR` region past 24 does not cover.
pub mod raw_tracepoint {
    pub const NAME:     usize = 0;
    pub const PROG_FD:  usize = 8;
    pub const COOKIE:   usize = 16;
    pub const LAST_END: usize = 24;
}
/// `BPF_PROG_STREAM_READ_BY_FD`; `LAST_FIELD prog_stream_read.prog_fd`.
pub mod prog_stream_read {
    pub const STREAM_BUF:     usize = 0;
    pub const STREAM_BUF_LEN: usize = 8;
    pub const STREAM_ID:      usize = 12;
    pub const PROG_FD:        usize = 16;
    pub const LAST_END:       usize = 20;
}
/// `BPF_PROG_ASSOC_STRUCT_OPS`; `LAST_FIELD prog_assoc_struct_ops.flags`.
pub mod prog_assoc_struct_ops {
    pub const MAP_FD:   usize = 0;
    pub const PROG_FD:  usize = 4;
    pub const FLAGS:    usize = 8;
    pub const LAST_END: usize = 12;
}
