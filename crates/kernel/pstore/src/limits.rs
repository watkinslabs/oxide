// Sizes, counts and bounds. Every one of them is a value the reference
// states somewhere (a module-parameter default, a Kconfig default, or a
// loop bound); none is a number invented here.

/// `MIN_MEM_SIZE` — the smallest a zone-carving request may be, and the
/// reference's default for each of its per-frontend sizes.
pub const MIN_MEM_SIZE: usize = 4096;

/// Default size of the whole reserved persistent region. The reference has
/// no default at all — a platform supplies `mem_address`/`mem_size` from
/// device tree — so this is the size the cmdline-free boot reserves, and
/// `ramoops.mem_size=` overrides it.
pub const DEFAULT_MEM_SIZE: usize = 256 * 1024;

/// `record_size` — how large ONE dmesg dump zone is. Sized above
/// [`DEFAULT_KMSG_BYTES`] so a default-sized log snapshot fits in a record
/// rather than being clipped by the zone.
pub const DEFAULT_RECORD_SIZE: usize = 32 * 1024;

/// `console_size` — the single zone every console byte-run is appended to.
pub const DEFAULT_CONSOLE_SIZE: usize = MIN_MEM_SIZE;

/// `CONFIG_PSTORE_DEFAULT_KMSG_BYTES` — how much of the kernel log a dmesg
/// record carries before `kmsg_bytes=` changes it.
pub const DEFAULT_KMSG_BYTES: u32 = 10240;

/// `ramoops_max_reason`'s effective default: a record is captured for a
/// reason at or below this one. Panic and oops are recorded; a shutdown or
/// an emergency restart is not, unless `ramoops.max_reason=` says so.
pub const DEFAULT_MAX_REASON: u8 = crate::uapi::DumpReason::Oops as u8;

/// `PSTORE_NAMELEN` — the buffer a record filename is rendered into.
pub const NAMELEN: usize = 64;

/// The reference's `stop_loop` guard on the enumeration walk: a backend that
/// never runs out of records must not hang the mount.
pub const MAX_RECORDS_PER_SCAN: usize = 65536;

/// Zone-header length in bytes: signature, start, size, checksum, each a
/// `u32` little-endian.
pub const ZONE_HDR_LEN: usize = 16;

/// Physical alignment the reserved region is placed and sized on.
pub const REGION_ALIGN: u64 = 4096;
