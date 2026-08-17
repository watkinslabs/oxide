//! One decoded request per command.
//!
//! Decoding is separated from admission so the two can be checked apart: a
//! payload that does not parse is a different failure from one that parses
//! and is refused, and Linux reports them in a fixed order that only a
//! separate decode step can reproduce.
//!
//! The indirect buffers a command names — a salt, a signature, a raw key, a
//! label string — arrive alongside the fixed payload, already fetched by the
//! copy layer per [`super::spec::Indirect`], so nothing here reads caller
//! memory.

use alloc::vec::Vec;

use syscall::errno::Errno;

use super::arg::{self, AddKey, FsxAttr, KeySpec, ReadMetadata, VerityEnableHead};
use super::uapi::*;

/// What the caller asked for, decoded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Req {
    StartAtomicWrite { replace: bool },
    CommitAtomicWrite,
    AbortAtomicWrite,
    /// Both volatile-write commands, which the format kept a number for and
    /// no longer implements anywhere.
    VolatileWrite,
    Shutdown(u32),
    Fitrim { start: u64, len: u64, minlen: u64 },
    SetEncryptionPolicy(Vec<u8>),
    GetEncryptionPolicy,
    GetEncryptionPolicyEx { capacity: u64 },
    GetEncryptionPwsalt,
    GetEncryptionNonce,
    AddEncryptionKey { key: AddKey, raw: Vec<u8> },
    RemoveEncryptionKey { spec: KeySpec, all_users: bool },
    GetEncryptionKeyStatus { spec: KeySpec },
    Gc { sync: bool },
    GcRange { sync: bool, start: u64, len: u64 },
    WriteCheckpoint,
    Defragment { start: u64, len: u64 },
    MoveRange { dst_fd: u32, pos_in: u64, pos_out: u64, len: u64 },
    FlushDevice { dev_num: u32, segments: u32 },
    GetFeatures,
    GetPinFile,
    SetPinFile(u32),
    PrecacheExtents,
    ResizeFs(u64),
    EnableVerity { head: VerityEnableHead, salt: Vec<u8>, sig: Vec<u8> },
    MeasureVerity { capacity: u16 },
    ReadVerityMetadata(ReadMetadata),
    GetFsLabel,
    SetFsLabel(Vec<u8>),
    GetCompressBlocks,
    ReleaseCompressBlocks,
    ReserveCompressBlocks,
    SecTrimFile { start: u64, len: u64, flags: u64 },
    GetCompressOption,
    SetCompressOption { algorithm: u8, log_cluster_size: u8 },
    DecompressFile,
    CompressFile,
    GetDevAliasFile,
    IoPrio(u32),
    GetVersion,
    SetVersion(u32),
    GetFlags,
    SetFlags(u32),
    FsGetXattr,
    FsSetXattr(FsxAttr),
}

/// The caller memory a command named through pointers inside its payload,
/// already fetched.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Extra {
    /// The verity salt, the raw key, or the label string, by command.
    pub first: Vec<u8>,
    /// The verity signature.
    pub second: Vec<u8>,
}

/// Turn a command and its fetched argument bytes into a request.
///
/// `cap_sys_admin` reaches the decoder only because two of the encryption
/// arguments interleave a capability test with their shape tests, and the
/// order between them is observable.
/// # C: O(payload bytes)
pub fn decode(cmd: u32, p: &[u8], x: &Extra, cap_sys_admin: bool) -> Result<Req, Errno> {
    Ok(match cmd {
        START_ATOMIC_WRITE => Req::StartAtomicWrite { replace: false },
        START_ATOMIC_REPLACE => Req::StartAtomicWrite { replace: true },
        COMMIT_ATOMIC_WRITE => Req::CommitAtomicWrite,
        ABORT_ATOMIC_WRITE => Req::AbortAtomicWrite,
        START_VOLATILE_WRITE | RELEASE_VOLATILE_WRITE => Req::VolatileWrite,
        SHUTDOWN => Req::Shutdown(arg::u32_at(p, 0)?),
        FITRIM => Req::Fitrim {
            start: arg::u64_at(p, 0)?,
            len: arg::u64_at(p, 8)?,
            minlen: arg::u64_at(p, 16)?,
        },
        SET_ENCRYPTION_POLICY => Req::SetEncryptionPolicy(p.to_vec()),
        GET_ENCRYPTION_POLICY => Req::GetEncryptionPolicy,
        GET_ENCRYPTION_POLICY_EX =>
            Req::GetEncryptionPolicyEx { capacity: arg::u64_at(p, POLICY_EX_SIZE_FIELD)? },
        GET_ENCRYPTION_PWSALT => Req::GetEncryptionPwsalt,
        GET_ENCRYPTION_NONCE => Req::GetEncryptionNonce,
        ADD_ENCRYPTION_KEY => {
            let key = arg::add_key(p, cap_sys_admin)?;
            // The copy layer fetched exactly `raw_size` bytes; a shorter one
            // means it could not, which is the caller's fault, not a shape
            // error in the argument.
            if x.first.len() != key.raw_size as usize { return Err(Errno::Efault); }
            Req::AddEncryptionKey { key, raw: x.first.clone() }
        }
        REMOVE_ENCRYPTION_KEY => Req::RemoveEncryptionKey {
            spec: arg::remove_key(p, cap_sys_admin)?, all_users: false,
        },
        REMOVE_ENCRYPTION_KEY_ALL_USERS => Req::RemoveEncryptionKey {
            spec: arg::remove_key(p, cap_sys_admin)?, all_users: true,
        },
        GET_ENCRYPTION_KEY_STATUS =>
            Req::GetEncryptionKeyStatus { spec: arg::key_status(p)? },
        GARBAGE_COLLECT => Req::Gc { sync: arg::u32_at(p, 0)? != 0 },
        GARBAGE_COLLECT_RANGE => Req::GcRange {
            sync: arg::u32_at(p, 0)? != 0,
            start: arg::u64_at(p, 8)?,
            len: arg::u64_at(p, 16)?,
        },
        WRITE_CHECKPOINT => Req::WriteCheckpoint,
        DEFRAGMENT => Req::Defragment { start: arg::u64_at(p, 0)?, len: arg::u64_at(p, 8)? },
        MOVE_RANGE => Req::MoveRange {
            dst_fd: arg::u32_at(p, 0)?,
            pos_in: arg::u64_at(p, 8)?,
            pos_out: arg::u64_at(p, 16)?,
            len: arg::u64_at(p, 24)?,
        },
        FLUSH_DEVICE => Req::FlushDevice {
            dev_num: arg::u32_at(p, 0)?, segments: arg::u32_at(p, 4)?,
        },
        GET_FEATURES => Req::GetFeatures,
        GET_PIN_FILE => Req::GetPinFile,
        SET_PIN_FILE => Req::SetPinFile(arg::u32_at(p, 0)?),
        PRECACHE_EXTENTS => Req::PrecacheExtents,
        RESIZE_FS => Req::ResizeFs(arg::u64_at(p, 0)?),
        ENABLE_VERITY => {
            let head = arg::verity_enable_head(p)?;
            if x.first.len() != head.salt_size as usize
                || x.second.len() != head.sig_size as usize
            { return Err(Errno::Efault); }
            Req::EnableVerity { head, salt: x.first.clone(), sig: x.second.clone() }
        }
        MEASURE_VERITY => Req::MeasureVerity { capacity: arg::u16_at(p, VD_SIZE)? },
        READ_VERITY_METADATA => Req::ReadVerityMetadata(arg::read_metadata(p)?),
        FS_IOC_GETFSLABEL => Req::GetFsLabel,
        FS_IOC_SETFSLABEL => Req::SetFsLabel(x.first.clone()),
        GET_COMPRESS_BLOCKS => Req::GetCompressBlocks,
        RELEASE_COMPRESS_BLOCKS => Req::ReleaseCompressBlocks,
        RESERVE_COMPRESS_BLOCKS => Req::ReserveCompressBlocks,
        SEC_TRIM_FILE => Req::SecTrimFile {
            start: arg::u64_at(p, 0)?, len: arg::u64_at(p, 8)?, flags: arg::u64_at(p, 16)?,
        },
        GET_COMPRESS_OPTION => Req::GetCompressOption,
        SET_COMPRESS_OPTION => Req::SetCompressOption {
            algorithm: arg::u8_at(p, 0)?, log_cluster_size: arg::u8_at(p, 1)?,
        },
        DECOMPRESS_FILE => Req::DecompressFile,
        COMPRESS_FILE => Req::CompressFile,
        GET_DEV_ALIAS_FILE => Req::GetDevAliasFile,
        IO_PRIO => Req::IoPrio(arg::u32_at(p, 0)?),
        FS_IOC_GETVERSION => Req::GetVersion,
        FS_IOC_SETVERSION => Req::SetVersion(arg::u32_at(p, 0)?),
        FS_IOC_GETFLAGS => Req::GetFlags,
        FS_IOC_SETFLAGS => Req::SetFlags(arg::u32_at(p, 0)?),
        FS_IOC_FSGETXATTR => Req::FsGetXattr,
        FS_IOC_FSSETXATTR => Req::FsSetXattr(arg::fsxattr(p)?),
        // Only a command this filesystem does not own reaches here, and that
        // is the one thing that may be reported as no such operation.
        _ => return Err(Errno::Enotty),
    })
}

#[cfg(test)]
#[path = "../tests/ioctl/decode.rs"]
mod tests;
