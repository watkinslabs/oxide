// FUSE wire protocol codec (FUSE UAPI) — the byte-faithful encode/
// decode of every request/reply struct the read-path daemon exchanges over the
// `/dev/fuse` channel. All integers are LITTLE-ENDIAN on the wire (the FUSE
// channel is host-endian; oxide targets are LE), packed with NO padding beyond
// the explicit `padding`/`dummy`/`spare` fields the C structs carry.
//
// Every opcode / flag / size is a NAMED constant (no magic numbers). Split for
// the 500-line file cap:
//   * this manifest — version/opcode/flag/size constants + LE scalar helpers.
//   * `message` — `fuse_in_header`, `fuse_out_header`, INIT handshake structs.
//   * `attr`    — `fuse_attr` + the entry/attr/open/read/dirent bodies.

extern crate alloc;
use alloc::vec::Vec;

mod message;
mod attr;

pub use message::{InHeader, OutHeader, InitIn, InitOut};
pub use attr::{Attr, EntryOut, AttrOut, OpenOut, OpenIn, GetattrIn, ReadIn, Dirent, decode_dirent_stream};

// ---------------------------------------------------------------------------
// Protocol version — Linux `FUSE_KERNEL_VERSION` / `FUSE_KERNEL_MINOR_VERSION`.
// ---------------------------------------------------------------------------

/// `FUSE_KERNEL_VERSION` — the wire major we speak. A daemon whose INIT major
/// differs is incompatible (Linux refuses with EPROTO). # C: O(1)
pub const FUSE_KERNEL_VERSION: u32 = 7;
/// `FUSE_KERNEL_MINOR_VERSION` — the highest minor this implementation supports.
/// We negotiate DOWN to the daemon's minor when it is lower. # C: O(1)
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 45;
/// `FUSE_ROOT_ID` — the nodeid of a mount's root inode. # C: O(1)
pub const FUSE_ROOT_ID: u64 = 1;

// ---------------------------------------------------------------------------
// `enum fuse_opcode` (FUSE UAPI) — the request opcodes. Only the ones
// this read-path implementation issues or recognises are named; the numeric
// values are the canonical libfuse assignments.
// ---------------------------------------------------------------------------

pub const FUSE_LOOKUP: u32 = 1;
pub const FUSE_FORGET: u32 = 2;
pub const FUSE_GETATTR: u32 = 3;
pub const FUSE_READLINK: u32 = 5;
pub const FUSE_OPEN: u32 = 14;
pub const FUSE_READ: u32 = 15;
pub const FUSE_STATFS: u32 = 17;
pub const FUSE_RELEASE: u32 = 18;
pub const FUSE_GETXATTR: u32 = 22;
pub const FUSE_FLUSH: u32 = 25;
pub const FUSE_INIT: u32 = 26;
pub const FUSE_OPENDIR: u32 = 27;
pub const FUSE_READDIR: u32 = 28;
pub const FUSE_RELEASEDIR: u32 = 29;
pub const FUSE_DESTROY: u32 = 38;

// ---------------------------------------------------------------------------
// `FUSE_*` INIT feature flags (subset this implementation advertises). The wire
// negotiation ANDs the daemon's advertised flags with ours.
// ---------------------------------------------------------------------------

/// `FUSE_ASYNC_READ` — asynchronous read requests permitted. # C: O(1)
pub const FUSE_ASYNC_READ: u32 = 1 << 0;
/// `FUSE_BIG_WRITES` — writes larger than one page permitted. # C: O(1)
pub const FUSE_BIG_WRITES: u32 = 1 << 5;
/// `FUSE_DO_READDIRPLUS` — daemon may answer READDIRPLUS. # C: O(1)
pub const FUSE_DO_READDIRPLUS: u32 = 1 << 13;
/// `FUSE_INIT_EXT` (7.36+) — the INIT request carries `flags2` and the reserved
/// extension area. Advertising 7.45 without this bit/body would lie about the
/// negotiated wire layout. # C: O(1)
pub const FUSE_INIT_EXT: u32 = 1 << 30;

// ---------------------------------------------------------------------------
// Fixed struct sizes (`sizeof` in libfuse) — the byte lengths the codec reads/
// writes. Named so the channel logic and tests share ONE source of truth.
// ---------------------------------------------------------------------------

/// `sizeof(struct fuse_in_header)`. # C: O(1)
pub const FUSE_IN_HEADER_SIZE: usize = 40;
/// `sizeof(struct fuse_out_header)`. # C: O(1)
pub const FUSE_OUT_HEADER_SIZE: usize = 16;
/// `sizeof(struct fuse_init_in)` for the pinned 7.45 ABI. # C: O(1)
pub const FUSE_INIT_IN_SIZE: usize = 64;
/// `sizeof(struct fuse_init_out)`. # C: O(1)
pub const FUSE_INIT_OUT_SIZE: usize = 64;
/// `sizeof(struct fuse_attr)`. # C: O(1)
pub const FUSE_ATTR_SIZE: usize = 88;
/// `sizeof(struct fuse_entry_out)` = 40 header + `fuse_attr`. # C: O(1)
pub const FUSE_ENTRY_OUT_SIZE: usize = 40 + FUSE_ATTR_SIZE;
/// `sizeof(struct fuse_attr_out)` = 16 header + `fuse_attr`. # C: O(1)
pub const FUSE_ATTR_OUT_SIZE: usize = 16 + FUSE_ATTR_SIZE;
/// `sizeof(struct fuse_getattr_in)`. # C: O(1)
pub const FUSE_GETATTR_IN_SIZE: usize = 16;
/// `sizeof(struct fuse_open_in)`. # C: O(1)
pub const FUSE_OPEN_IN_SIZE: usize = 8;
/// `sizeof(struct fuse_open_out)`. # C: O(1)
pub const FUSE_OPEN_OUT_SIZE: usize = 16;
/// `sizeof(struct fuse_read_in)`. # C: O(1)
pub const FUSE_READ_IN_SIZE: usize = 40;
/// `sizeof(struct fuse_release_in)`. # C: O(1)
pub const FUSE_RELEASE_IN_SIZE: usize = 24;
/// `sizeof(struct fuse_flush_in)`. # C: O(1)
pub const FUSE_FLUSH_IN_SIZE: usize = 24;
/// `sizeof(struct fuse_forget_in)`. # C: O(1)
pub const FUSE_FORGET_IN_SIZE: usize = 8;
/// `struct fuse_dirent` header size (`ino,off,namelen,type`), name follows.
/// # C: O(1)
pub const FUSE_DIRENT_HEADER_SIZE: usize = 24;

/// `FUSE_DIRENT_ALIGN(x)` — round `x` up to an 8-byte boundary (Linux
/// `#define FUSE_DIRENT_ALIGN(x) (((x)+sizeof(u64)-1) & ~(sizeof(u64)-1))`).
/// # C: O(1)
pub const fn fuse_dirent_align(x: usize) -> usize { (x + 7) & !7 }

// ---------------------------------------------------------------------------
// Little-endian scalar helpers. A tiny append/read cursor keeps the struct
// encoders declarative without a serde dependency (`no_std`).
// ---------------------------------------------------------------------------

/// Append `v` little-endian to `out`. # C: O(1)
pub fn put_u32(out: &mut Vec<u8>, v: u32) { out.extend_from_slice(&v.to_le_bytes()); }
/// Append `v` little-endian to `out`. # C: O(1)
pub fn put_u64(out: &mut Vec<u8>, v: u64) { out.extend_from_slice(&v.to_le_bytes()); }
/// Append `v` little-endian to `out`. # C: O(1)
pub fn put_u16(out: &mut Vec<u8>, v: u16) { out.extend_from_slice(&v.to_le_bytes()); }
/// Append `n` zero bytes (explicit `padding`/`spare` fields). # C: O(n)
pub fn put_pad(out: &mut Vec<u8>, n: usize) { out.extend(core::iter::repeat(0u8).take(n)); }

/// Read a little-endian `u32` at byte `off` of `b`; `None` if truncated.
/// # C: O(1)
pub fn get_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
/// Read a little-endian `u64` at byte `off` of `b`; `None` if truncated.
/// # C: O(1)
pub fn get_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8).map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}
/// Read a little-endian `u16` at byte `off` of `b`; `None` if truncated.
/// # C: O(1)
pub fn get_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
