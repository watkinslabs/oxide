// userfaultfd(2) UAPI — verbatim from Linux `include/uapi/linux/userfaultfd.h`
// (v7.2.0-rc4). Numbers only; every policy decision lives in `policy.rs`.
//
// Deliberately UNGATED (no `target_os = "oxide-kernel"`), so the hosted
// `cargo test` build compiles these constants and the policy tests that
// consume them.

/// `UFFD_API` — the only API version `UFFDIO_API` accepts.
pub const UFFD_API: u64 = 0xAA;

/// `_UFFDIO_*` command slot numbers. These are the BIT INDEXES each op
/// occupies in the `uffdio_api.ioctls` / `uffdio_register.ioctls` reply
/// bitmaps — NOT the ioctl request numbers.
pub mod slot {
    pub const REGISTER:     u32 = 0x00;
    pub const UNREGISTER:   u32 = 0x01;
    pub const WAKE:         u32 = 0x02;
    pub const COPY:         u32 = 0x03;
    pub const ZEROPAGE:     u32 = 0x04;
    pub const MOVE:         u32 = 0x05;
    pub const WRITEPROTECT: u32 = 0x06;
    pub const CONTINUE:     u32 = 0x07;
    pub const POISON:       u32 = 0x08;
    pub const API:          u32 = 0x3F;
}

/// `UFFD_API_IOCTLS` — ops valid on the fd itself, reported by `UFFDIO_API`.
pub const UFFD_API_IOCTLS: u64 =
    (1u64 << slot::REGISTER) | (1u64 << slot::UNREGISTER) | (1u64 << slot::API);

/// `UFFD_API_RANGE_IOCTLS` restricted to the ops this kernel actually
/// implements. Linux also lists MOVE/WRITEPROTECT/CONTINUE/POISON; those are
/// absent here, so advertising them would make a monitor issue an ioctl that
/// cannot work. The `uffdio_register.ioctls` reply is a PROMISE ("guaranteed
/// to succeed on this range" — `mm/userfaultfd.c` `userfaultfd_register`), so
/// it must name only implemented ops.
pub const UFFD_API_RANGE_IOCTLS: u64 =
    (1u64 << slot::WAKE) | (1u64 << slot::COPY) | (1u64 << slot::ZEROPAGE);

// ioctl request numbers (`_IOWR(UFFDIO, _UFFDIO_x, struct ...)`). The size
// field of each encoding is the authoritative struct size — e.g. UFFDIO_API's
// 0x18 is 24, which is why `uffdio_api` is three u64s, not two.
pub const UFFDIO_API:        u64 = 0xc018_aa3f;
pub const UFFDIO_REGISTER:   u64 = 0xc020_aa00;
pub const UFFDIO_UNREGISTER: u64 = 0x8010_aa01;
pub const UFFDIO_WAKE:       u64 = 0x8010_aa02;
pub const UFFDIO_COPY:       u64 = 0xc028_aa03;
pub const UFFDIO_ZEROPAGE:   u64 = 0xc020_aa04;

/// `struct uffdio_api` — `{ api, features, ioctls }`, 24 bytes.
pub const UFFDIO_API_SIZE:       u64 = 24;
/// `struct uffdio_range` — `{ start, len }`.
pub const UFFDIO_RANGE_SIZE:     u64 = 16;
/// `struct uffdio_register` — `{ range, mode, ioctls }`.
pub const UFFDIO_REGISTER_SIZE:  u64 = 32;
/// `struct uffdio_copy` — `{ dst, src, len, mode, copy }`.
pub const UFFDIO_COPY_SIZE:      u64 = 40;
/// `struct uffdio_zeropage` — `{ range, mode, zeropage }`.
pub const UFFDIO_ZEROPAGE_SIZE:  u64 = 32;

/// Byte offset of the kernel-written `uffdio_register.ioctls` reply.
pub const UFFDIO_REGISTER_IOCTLS_OFF: u64 = 24;
/// Byte offset of the kernel-written `uffdio_copy.copy` reply.
pub const UFFDIO_COPY_COPY_OFF:       u64 = 32;
/// Byte offset of the kernel-written `uffdio_zeropage.zeropage` reply.
pub const UFFDIO_ZEROPAGE_ZEROPAGE_OFF: u64 = 24;

/// `uffdio_register.mode` bits.
pub const UFFDIO_REGISTER_MODE_MISSING: u64 = 1 << 0;
pub const UFFDIO_REGISTER_MODE_WP:      u64 = 1 << 1;
pub const UFFDIO_REGISTER_MODE_MINOR:   u64 = 1 << 2;
/// `UFFD_API_REGISTER_MODES` — every mode bit Linux's UAPI defines.
pub const UFFD_API_REGISTER_MODES: u64 =
    UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP | UFFDIO_REGISTER_MODE_MINOR;

/// `uffdio_copy.mode` bits.
pub const UFFDIO_COPY_MODE_DONTWAKE: u64 = 1 << 0;
pub const UFFDIO_COPY_MODE_WP:       u64 = 1 << 1;
/// `uffdio_zeropage.mode` bits.
pub const UFFDIO_ZEROPAGE_MODE_DONTWAKE: u64 = 1 << 0;

/// `UFFD_FEATURE_*` bits.
pub mod feature {
    pub const PAGEFAULT_FLAG_WP:  u64 = 1 << 0;
    pub const EVENT_FORK:         u64 = 1 << 1;
    pub const EVENT_REMAP:        u64 = 1 << 2;
    pub const EVENT_REMOVE:       u64 = 1 << 3;
    pub const MISSING_HUGETLBFS:  u64 = 1 << 4;
    pub const MISSING_SHMEM:      u64 = 1 << 5;
    pub const EVENT_UNMAP:        u64 = 1 << 6;
    pub const SIGBUS:             u64 = 1 << 7;
    pub const THREAD_ID:          u64 = 1 << 8;
    pub const MINOR_HUGETLBFS:    u64 = 1 << 9;
    pub const MINOR_SHMEM:        u64 = 1 << 10;
    pub const EXACT_ADDRESS:      u64 = 1 << 11;
    pub const WP_HUGETLBFS_SHMEM: u64 = 1 << 12;
    pub const WP_UNPOPULATED:     u64 = 1 << 13;
    pub const POISON:             u64 = 1 << 14;
    pub const WP_ASYNC:           u64 = 1 << 15;
    pub const MOVE:               u64 = 1 << 16;
    /// `UFFD_FEATURE_INITIALIZED` (`mm/userfaultfd.c`) — kernel-internal, never
    /// visible to userspace; ORed into `ctx->features` by `uffd_ctx_features`
    /// so `userfaultfd_is_initialized` can tell "UFFDIO_API ran" from
    /// "features == 0".
    pub const INITIALIZED:        u64 = 1 << 31;
}

/// Feature bits this kernel can honour. Linux reports `UFFD_API_FEATURES`
/// (every bit it implements) and then EINVALs a request for anything outside
/// it; the honest oxide answer is the set actually wired: `THREAD_ID` (the
/// faulting tid is already recorded in `uffd_msg.arg.pagefault.feat.ptid`).
/// MISSING-mode pagefault delivery and `UFFD_PAGEFAULT_FLAG_WRITE` are
/// implicitly always enabled and carry no feature bit.
pub const UFFD_API_FEATURES: u64 = feature::THREAD_ID;

/// `uffd_msg.event` values.
pub const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
/// `uffd_msg.arg.pagefault.flags` bits.
pub const UFFD_PAGEFAULT_FLAG_WRITE: u64 = 1 << 0;
pub const UFFD_PAGEFAULT_FLAG_WP:    u64 = 1 << 1;
pub const UFFD_PAGEFAULT_FLAG_MINOR: u64 = 1 << 2;

/// `UFFD_USER_MODE_ONLY` (`include/uapi/linux/userfaultfd.h`) — the fd may
/// only intercept faults taken from user mode; a kernel-mode access to a
/// registered range gets `VM_FAULT_SIGBUS` instead of being handed to the
/// monitor.
pub const UFFD_USER_MODE_ONLY: u32 = 1;
/// `UFFD_SHARED_FCNTL_FLAGS` (`include/linux/userfaultfd_k.h`).
pub const O_CLOEXEC:  u32 = 0o2_000_000;
pub const O_NONBLOCK: u32 = 0o0_004_000;
pub const UFFD_SHARED_FCNTL_FLAGS: u32 = O_CLOEXEC | O_NONBLOCK;
/// Every `userfaultfd(2)` flag Linux accepts.
pub const UFFD_ALL_FLAGS: u32 = UFFD_SHARED_FCNTL_FLAGS | UFFD_USER_MODE_ONLY;
