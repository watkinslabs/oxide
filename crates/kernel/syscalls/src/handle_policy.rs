// name_to_handle_at(2) 303 / open_by_handle_at(2) 304 — the `struct
// file_handle` ABI, the FID codec, and both syscalls' admission ladders.
//
// Both slot files are kernel-gated, so every DECISION lives here where the
// hosted suite can assert it (CLAUDE.md phantom-test rule, docs/53).
//
//   struct file_handle { __u32 handle_bytes; int handle_type; unsigned char f_handle[]; }
//
// Module manifest:
//   flags  — `name_to_handle_at` flag masks, `HandleOpts`, the capacity protocol
//   fid    — the FID layout this kernel encodes and its codec
//   decode — `open_by_handle_at` header validation + the `may_decode_fh` ladder
//   acceptable — the decoded object's reach test (idmapped owner + containment)

pub mod flags;
pub mod decode;
pub mod acceptable;

/// The FID codec lives in `vfs::export::fid`: fanotify's `FAN_REPORT_FID` info
/// records encode the same handle, and two encoders would hand userspace a fid
/// that `open_by_handle_at` cannot decode.
pub use vfs::export::fid;

pub use flags::{AT_EMPTY_PATH, AT_HANDLE_CONNECTABLE, AT_HANDLE_FID, AT_HANDLE_MNT_ID_UNIQUE,
    AT_HANDLE_VALID, AT_SYMLINK_FOLLOW, HANDLE_HDR, HandleOpts, MAX_HANDLE_SZ,
    handle_capacity_check, name_to_handle_flags_check};
pub use fid::{FID_LEN, FID_LEN_PARENT, Fid, HANDLE_TYPE_INO_GEN, HANDLE_TYPE_INO_GEN_PARENT,
    decode_fid, encode_fid, encoded_fid_len, fid_len_for_type};
pub use acceptable::{dentry_acceptable, inode_owner_reachable};
pub use decode::{DecodeCtx, FILEID_IS_CONNECTABLE, FILEID_IS_DIR, FILEID_USER_FLAGS_MASK,
    FILEID_VALID_USER_FLAGS, MayDecodeFh, handle_header_check, header_is_our_fid, may_decode_fh,
    strip_user_flags};

#[cfg(test)]
mod tests;
