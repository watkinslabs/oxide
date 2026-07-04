use core::sync::atomic::AtomicPtr;

use crate::RequestId;

/// Common request header. Bootloader matches on `id`; on hit, sets
/// `response` to the physical address of a feature-specific
/// response struct.
#[repr(C)]
pub struct RequestHeader<R> {
    pub id:       RequestId,
    pub revision: u64,
    pub response: AtomicPtr<R>,
}

// SAFETY: `RequestHeader` is shared with the bootloader before any
// CPU other than the boot CPU is alive; afterwards it is read-only
// from the kernel side. The `AtomicPtr` is the bootloader's write
// port. Response payloads contain raw pointers that aren't `Sync`
// by default — the bootloader writes them once and the kernel reads
// them serially, so we assert `Sync` unconditionally on the wrapper.
unsafe impl<R> Sync for RequestHeader<R> {}

/// `LimineFile` per limine-protocol/include/limine.h. Bootloader-
/// allocated; pointers reference bootloader-owned memory that stays
/// valid until BootloaderReclaimable regions are recycled.
#[repr(C)]
pub struct LimineFile {
    pub revision:     u64,
    pub address:      *const u8,
    pub size:         u64,
    pub path:         *const u8,
    pub cmdline:      *const u8,
    pub media_type:   u32,
    pub _unused:      u32,
    pub tftp_ip:      u32,
    pub tftp_port:    u32,
    pub partition_index: u32,
    pub mbr_disk_id:  u32,
    pub gpt_disk_uuid: [u64; 2],
    pub gpt_part_uuid: [u64; 2],
    pub part_uuid:    [u64; 2],
}

/// `EXECUTABLE_FILE` response. The `executable_file` pointer
/// references a bootloader-allocated `LimineFile`.
#[repr(C)]
pub struct ExecutableFileResponse {
    pub revision:        u64,
    pub executable_file: *const LimineFile,
}
