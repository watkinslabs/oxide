// perf_event ABI numbers — Linux `include/uapi/linux/perf_event.h`.
// Numbers only; every policy decision lives in `attr.rs`/`perm.rs`/`open.rs`.

#![allow(dead_code)]

/// `enum perf_type_id`.
pub mod ptype {
    pub const HARDWARE:   u32 = 0;
    pub const SOFTWARE:   u32 = 1;
    pub const TRACEPOINT: u32 = 2;
    pub const HW_CACHE:   u32 = 3;
    pub const RAW:        u32 = 4;
    pub const BREAKPOINT: u32 = 5;
    pub const MAX:        u32 = 6;
}

/// `enum perf_sw_ids`.
pub mod sw {
    pub const CPU_CLOCK:        u64 = 0;
    pub const TASK_CLOCK:       u64 = 1;
    pub const PAGE_FAULTS:      u64 = 2;
    pub const CONTEXT_SWITCHES: u64 = 3;
    pub const CPU_MIGRATIONS:   u64 = 4;
    pub const PAGE_FAULTS_MIN:  u64 = 5;
    pub const PAGE_FAULTS_MAJ:  u64 = 6;
    pub const ALIGNMENT_FAULTS: u64 = 7;
    pub const EMULATION_FAULTS: u64 = 8;
    pub const DUMMY:            u64 = 9;
    pub const BPF_OUTPUT:       u64 = 10;
    pub const CGROUP_SWITCHES:  u64 = 11;
    pub const MAX:              u64 = 12;
}

/// `enum perf_event_read_format`.
pub mod fmt {
    pub const TOTAL_TIME_ENABLED: u64 = 1 << 0;
    pub const TOTAL_TIME_RUNNING: u64 = 1 << 1;
    pub const ID:                 u64 = 1 << 2;
    pub const GROUP:              u64 = 1 << 3;
    pub const LOST:               u64 = 1 << 4;
    pub const MAX:                u64 = 1 << 5;
}

/// `enum perf_event_sample_format` — only the bits the open path branches on,
/// plus the validity ceiling.
pub mod sample {
    pub const READ:         u64 = 1 << 4;
    pub const BRANCH_STACK: u64 = 1 << 11;
    pub const REGS_USER:    u64 = 1 << 12;
    pub const STACK_USER:   u64 = 1 << 13;
    pub const WEIGHT:       u64 = 1 << 14;
    pub const REGS_INTR:    u64 = 1 << 18;
    pub const PHYS_ADDR:    u64 = 1 << 19;
    pub const CGROUP:       u64 = 1 << 21;
    pub const WEIGHT_STRUCT:u64 = 1 << 24;
    pub const MAX:          u64 = 1 << 25;
}

/// `enum perf_branch_sample_type` — priv-level bits + ceiling.
pub mod branch {
    pub const USER:     u64 = 1 << 0;
    pub const KERNEL:   u64 = 1 << 1;
    pub const HV:       u64 = 1 << 2;
    /// `PERF_SAMPLE_BRANCH_PLM_ALL`.
    pub const PLM_ALL:  u64 = USER | KERNEL | HV;
    /// `PERF_SAMPLE_BRANCH_PERM_PLM` (`kernel/events/core.c`).
    pub const PERM_PLM: u64 = KERNEL | HV;
    /// `1U << PERF_SAMPLE_BRANCH_MAX_SHIFT` (shift 20).
    pub const MAX:      u64 = 1 << 20;
}

/// `perf_event_open` flags word.
pub mod open_flags {
    pub const FD_NO_GROUP: u64 = 1 << 0;
    pub const FD_OUTPUT:   u64 = 1 << 1;
    pub const PID_CGROUP:  u64 = 1 << 2;
    pub const FD_CLOEXEC:  u64 = 1 << 3;
    /// `PERF_FLAG_ALL` (`kernel/events/core.c`).
    pub const ALL: u64 = FD_NO_GROUP | FD_OUTPUT | PID_CGROUP | FD_CLOEXEC;
}

/// `PERF_EVENT_IOC_*` — `_IO*('$', n)`, `'$'` = 0x24.
pub mod ioc {
    pub const ENABLE:            u64 = 0x2400;
    pub const DISABLE:           u64 = 0x2401;
    pub const REFRESH:           u64 = 0x2402;
    pub const RESET:             u64 = 0x2403;
    pub const PERIOD:            u64 = 0x4008_2404;
    pub const SET_OUTPUT:        u64 = 0x2405;
    pub const SET_FILTER:        u64 = 0x4008_2406;
    pub const ID:                u64 = 0x8008_2407;
    pub const SET_BPF:           u64 = 0x4004_2408;
    pub const PAUSE_OUTPUT:      u64 = 0x4004_2409;
    pub const QUERY_BPF:         u64 = 0xC008_240A;
    pub const MODIFY_ATTRIBUTES: u64 = 0x4008_240B;
    /// `PERF_IOC_FLAG_GROUP`.
    pub const FLAG_GROUP: u64 = 1 << 0;
}

/// `PERF_ATTR_SIZE_VER*` plus the size of the current `struct perf_event_attr`.
pub mod attr_size {
    pub const VER0: u32 = 64;
    pub const VER1: u32 = 72;
    pub const VER2: u32 = 80;
    pub const VER3: u32 = 96;
    pub const VER4: u32 = 104;
    pub const VER5: u32 = 112;
    pub const VER6: u32 = 120;
    pub const VER7: u32 = 128;
    pub const VER8: u32 = 136;
    /// `sizeof(struct perf_event_attr)` as of v7.2 (VER8 + `config4`).
    pub const CURRENT: u32 = 144;
    /// `perf_copy_attr` ceiling is `PAGE_SIZE`.
    pub const CEILING: u32 = 4096;
}

/// Byte offsets inside `struct perf_event_attr` (x86_64/aarch64 LP64 layout).
pub mod attr_off {
    pub const TYPE:               usize = 0;
    pub const SIZE:               usize = 4;
    pub const CONFIG:             usize = 8;
    pub const SAMPLE_PERIOD:      usize = 16;
    pub const SAMPLE_TYPE:        usize = 24;
    pub const READ_FORMAT:        usize = 32;
    pub const BITS:               usize = 40;
    pub const WAKEUP_EVENTS:      usize = 48;
    pub const BP_TYPE:            usize = 52;
    pub const CONFIG1:            usize = 56;
    pub const CONFIG2:            usize = 64;
    pub const BRANCH_SAMPLE_TYPE: usize = 72;
    pub const SAMPLE_REGS_USER:   usize = 80;
    pub const SAMPLE_STACK_USER:  usize = 88;
    pub const CLOCKID:            usize = 92;
    pub const SAMPLE_REGS_INTR:   usize = 96;
    pub const AUX_WATERMARK:      usize = 104;
    pub const SAMPLE_MAX_STACK:   usize = 108;
    pub const RESERVED_2:         usize = 110;
    pub const AUX_SAMPLE_SIZE:    usize = 112;
    pub const AUX_ACTION:         usize = 116;
    pub const SIG_DATA:           usize = 120;
    pub const CONFIG3:            usize = 128;
    pub const CONFIG4:            usize = 136;
}

/// Bit positions inside the 64-bit `perf_event_attr` bitfield word at
/// `attr_off::BITS`, in declaration order.
pub mod attr_bit {
    pub const DISABLED:       u32 = 0;
    pub const INHERIT:        u32 = 1;
    pub const PINNED:         u32 = 2;
    pub const EXCLUSIVE:      u32 = 3;
    pub const EXCLUDE_USER:   u32 = 4;
    pub const EXCLUDE_KERNEL: u32 = 5;
    pub const EXCLUDE_HV:     u32 = 6;
    pub const EXCLUDE_IDLE:   u32 = 7;
    pub const MMAP:           u32 = 8;
    pub const COMM:           u32 = 9;
    pub const FREQ:           u32 = 10;
    pub const INHERIT_STAT:   u32 = 11;
    pub const ENABLE_ON_EXEC: u32 = 12;
    pub const TASK:           u32 = 13;
    pub const WATERMARK:      u32 = 14;
    /// 2-bit `precise_ip` field at 15..16.
    pub const PRECISE_IP:     u32 = 15;
    pub const MMAP_DATA:      u32 = 17;
    pub const SAMPLE_ID_ALL:  u32 = 18;
    pub const EXCLUDE_HOST:   u32 = 19;
    pub const EXCLUDE_GUEST:  u32 = 20;
    pub const EXCL_CALLCHAIN_KERNEL: u32 = 21;
    pub const EXCL_CALLCHAIN_USER:   u32 = 22;
    pub const MMAP2:          u32 = 23;
    pub const COMM_EXEC:      u32 = 24;
    pub const USE_CLOCKID:    u32 = 25;
    pub const CONTEXT_SWITCH: u32 = 26;
    pub const WRITE_BACKWARD: u32 = 27;
    pub const NAMESPACES:     u32 = 28;
    pub const KSYMBOL:        u32 = 29;
    pub const BPF_EVENT:      u32 = 30;
    pub const AUX_OUTPUT:     u32 = 31;
    pub const CGROUP:         u32 = 32;
    pub const TEXT_POKE:      u32 = 33;
    pub const BUILD_ID:       u32 = 34;
    pub const INHERIT_THREAD: u32 = 35;
    pub const REMOVE_ON_EXEC: u32 = 36;
    pub const SIGTRAP:        u32 = 37;
    pub const DEFER_CALLCHAIN:u32 = 38;
    pub const DEFER_OUTPUT:   u32 = 39;
    /// `__reserved_1 : 24` occupies 40..63.
    pub const RESERVED_1_SHIFT: u32 = 40;
    pub const RESERVED_1_MASK:  u64 = !0u64 << RESERVED_1_SHIFT;
    /// `aux_action` `__reserved_3 : 29` occupies bits 3..31 of that u32.
    pub const AUX_RESERVED_3_MASK: u32 = !0u32 << 3;
}

/// `clockid_t` values `perf_event_set_clock` accepts.
pub mod clockid {
    pub const REALTIME:      i32 = 0;
    pub const MONOTONIC:     i32 = 1;
    pub const MONOTONIC_RAW: i32 = 4;
    pub const BOOTTIME:      i32 = 7;
    pub const TAI:           i32 = 11;
}

/// `struct perf_event_mmap_page` — the ring control page.
pub mod mmap_page {
    pub const OFF_VERSION:        usize = 0;
    pub const OFF_COMPAT_VERSION: usize = 4;
    pub const OFF_LOCK:           usize = 8;
    pub const OFF_INDEX:          usize = 12;
    pub const OFF_OFFSET:         usize = 16;
    pub const OFF_TIME_ENABLED:   usize = 24;
    pub const OFF_TIME_RUNNING:   usize = 32;
    pub const OFF_CAPABILITIES:   usize = 40;
    pub const OFF_DATA_HEAD:      usize = 1024;
    pub const OFF_DATA_TAIL:      usize = 1032;
    pub const OFF_DATA_OFFSET:    usize = 1040;
    pub const OFF_DATA_SIZE:      usize = 1048;
    /// `cap_user_time`/`cap_user_rdpmc` all clear: userspace must use `read(2)`.
    pub const CAP_NONE: u64 = 0;
    pub const VERSION:  u32 = 0;
}

/// `perf_reg_validate` rejection mask — a nonzero `sample_regs_*` that
/// intersects `REJECT` is `-EINVAL`; a zero mask is `-EINVAL` too.
///
/// x86_64 (`arch/x86/kernel/perf_regs.c`): `REG_NOSUPPORT` = DS/ES/FS/GS
/// (bits 12..15); `PERF_REG_X86_RESERVED` folds to 0 there because
/// `PERF_REG_X86_MAX` is 64 — the XMM bits 32..63 are therefore *accepted*.
///
/// aarch64 (`arch/arm64/kernel/perf_regs.c`): `REG_RESERVED` =
/// `~((1 << PERF_REG_ARM64_MAX) - 1)` with `PERF_REG_ARM64_MAX` = 33
/// (x0..x29, LR, SP, PC). The SVE `PERF_REG_ARM64_VG` bit (46) is only
/// unreserved when `system_supports_sve()`, which oxide does not claim.
pub mod regs {
    #[cfg(not(target_arch = "aarch64"))]
    pub const REJECT: u64 = (1 << 12) | (1 << 13) | (1 << 14) | (1 << 15);
    #[cfg(target_arch = "aarch64")]
    pub const REJECT: u64 = !((1u64 << 33) - 1);
}
