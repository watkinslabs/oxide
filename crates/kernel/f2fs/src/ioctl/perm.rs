//! Who may issue each command, and in what ORDER the refusals happen.
//!
//! The order is as much of the contract as the errno is. A caller with no
//! capability sending a malformed argument must be told which of the two
//! stopped it, because the two mean different things: one is "you may not",
//! the other is "that is not a request". Programs branch on the difference,
//! so a ladder that checks the cheap test first because it is cheap reports
//! the wrong one.
//!
//! Every check here is a pure function of stated facts, so the whole ladder
//! is exercised without a mounted volume, a descriptor or a caller.

use syscall::errno::Errno;

use super::req::Req;
use super::uapi::*;

/// What the descriptor a move names turns out to be.
///
/// Three outcomes, not two, because the two ways a destination can be wrong
/// are refused at DIFFERENT rungs: a descriptor that does not exist or cannot
/// be written is not a usable descriptor at all and is refused before the
/// mount's write reference is taken, while one that is perfectly good but
/// names another mount or another volume is refused after it, with the errno
/// that says "not on this filesystem". Collapsing the two reports the wrong
/// one, and a caller branches on the difference.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum DstFd {
    /// No such descriptor, or one not opened for writing.
    #[default]
    Unusable,
    /// A descriptor on another mount, or on another volume of this
    /// filesystem.
    Foreign,
    /// A file of the same volume, by inode number.
    Ours(u32),
}

/// What the caller and its open description are, as the ladder reads them.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Ctx {
    pub cap_sys_admin: bool,
    /// The description was opened for reading.
    pub fmode_read: bool,
    /// The description was opened for writing.
    pub fmode_write: bool,
    /// The description bypasses the page cache.
    pub o_direct: bool,
    /// The caller owns the inode or holds the capability that stands in for
    /// ownership.
    pub owner_or_capable: bool,
    /// Taking a write reference on the mount would succeed; false is the
    /// read-only mount every write-bearing command must refuse against.
    pub mnt_writable: bool,
    /// Open descriptions currently holding this inode for writing.
    pub writecount: u32,
    /// Pages of this inode dirty right now.
    pub dirty_pages: u64,
    /// The inode is mapped by some address space.
    pub mmapped: bool,
    /// What the second descriptor a move names resolved to. Meaningless for
    /// every other command, and resolved by the layer that owns descriptors —
    /// this one has none.
    pub dst: DstFd,
}

/// What the volume is, as the ladder reads it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct VolFacts {
    pub features: u32,
    /// The volume was mounted writable.
    pub writable: bool,
    /// The last checkpoint recorded an error, which makes every command fail
    /// before it is even looked at.
    pub cp_error: bool,
    /// Checkpointing is switched off, which several administrative commands
    /// refuse rather than silently skip.
    pub cp_disabled: bool,
    /// There is room to take a checkpoint if one is needed.
    pub checkpoint_ready: bool,
    pub supports_discard: bool,
    /// Devices the volume spans, one for an ordinary volume.
    pub device_count: u32,
    /// Sections hold more than one segment.
    pub large_section: bool,
    /// Compression is driven by the caller rather than by the mount.
    pub compress_mode_user: bool,
    /// A codec for this volume's compressed clusters is present.
    pub compress_backend_ready: bool,
    /// First and last block of the main area, which bound a range request.
    pub main_blkaddr: u64,
    pub max_blkaddr: u64,
    /// Blocks one file may hold, which bounds a defragment range.
    pub max_file_blocks: u64,
}

impl VolFacts {
    /// The volume spans more than one device. # C: O(1)
    pub fn multi_device(&self) -> bool { self.device_count > 1 }
}

/// What the file is, as the ladder reads it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct FileFacts {
    pub is_reg: bool,
    pub is_dir: bool,
    pub size: u64,
    /// The file holds at least one data block.
    pub has_blocks: bool,
    pub atomic: bool,
    pub compressed: bool,
    pub compress_released: bool,
    /// Blocks this file's compressed clusters saved, zero when none.
    pub compr_blocks: u64,
    pub pinned: bool,
    pub verity: bool,
    pub encrypted: bool,
    pub immutable: bool,
    pub append_only: bool,
    /// The file stands for a whole device rather than for its own data.
    pub device_alias: bool,
    /// Extent caching is switched off for this file.
    pub no_extent: bool,
    /// Data still lives inside the inode rather than in blocks.
    pub inline_data: bool,
}

/// The block size every alignment rule here is stated in.
const BLKSIZE: u64 = crate::uapi::BLKSIZE as u64;

/// The two conditions that stop EVERY command before it is dispatched.
///
/// A volume whose last checkpoint recorded an error cannot answer for
/// anything on it, and one with no room to checkpoint cannot complete a
/// command that would need to. Both are checked once, ahead of the switch,
/// so no command can forget them.
/// # C: O(1)
pub fn prologue(v: &VolFacts) -> Result<(), Errno> {
    if v.cp_error { return Err(Errno::Eio); }
    if !v.checkpoint_ready { return Err(Errno::Enospc); }
    Ok(())
}

/// May this request proceed? The first refusal wins, and its position in the
/// ladder is the contract. # C: O(1)
pub fn admit(r: &Req, c: &Ctx, v: &VolFacts, f: &FileFacts) -> Result<(), Errno> {
    match r {
        Req::VolatileWrite => Err(Errno::Eopnotsupp),

        Req::StartAtomicWrite { .. } => {
            if !c.fmode_write { return Err(Errno::Ebadf); }
            if !c.owner_or_capable { return Err(Errno::Eacces); }
            if !f.is_reg { return Err(Errno::Einval); }
            // Atomic writes are staged in the page cache until they are
            // committed, so a description that bypasses it has nowhere to
            // stage them and would write through, defeating the whole point.
            if c.o_direct { return Err(Errno::Einval); }
            want_write(c)?;
            // A compressed or pinned file cannot be staged: one has clusters
            // that only mean anything whole, the other has addresses that
            // must not move.
            if f.compressed || f.pinned { return Err(Errno::Einval); }
            Ok(())
        }
        Req::CommitAtomicWrite | Req::AbortAtomicWrite => {
            if !c.fmode_write { return Err(Errno::Ebadf); }
            if !c.owner_or_capable { return Err(Errno::Eacces); }
            want_write(c)
        }

        Req::Shutdown(mode) => {
            if !c.cap_sys_admin { return Err(Errno::Eperm); }
            if *mode >= GOING_DOWN_MAX { return Err(Errno::Einval); }
            // A full-sync shutdown freezes the device rather than writing
            // through the mount, so it does not need a write reference and
            // works on a read-only mount. Every other mode does need one,
            // and a read-only mount downgrades it rather than refusing.
            Ok(())
        }

        Req::Fitrim { .. } => {
            if !c.cap_sys_admin { return Err(Errno::Eperm); }
            if !v.supports_discard { return Err(Errno::Eopnotsupp); }
            want_write(c)
        }

        Req::SetEncryptionPolicy(_) | Req::GetEncryptionPolicy
        | Req::GetEncryptionPolicyEx { .. } | Req::GetEncryptionNonce
        | Req::AddEncryptionKey { .. } | Req::RemoveEncryptionKey { .. }
        | Req::GetEncryptionKeyStatus { .. } => encrypt_enabled(v),
        Req::GetEncryptionPwsalt => { encrypt_enabled(v)?; want_write(c) }

        Req::Gc { .. } => {
            if !c.cap_sys_admin { return Err(Errno::Eperm); }
            if !v.writable { return Err(Errno::Erofs); }
            want_write(c)
        }
        Req::GcRange { start, len, .. } => {
            if !c.cap_sys_admin { return Err(Errno::Eperm); }
            if !v.writable { return Err(Errno::Erofs); }
            let end = start.checked_add(*len).ok_or(Errno::Einval)?;
            if *start < v.main_blkaddr || end >= v.max_blkaddr { return Err(Errno::Einval); }
            want_write(c)
        }
        Req::WriteCheckpoint => {
            if !c.cap_sys_admin { return Err(Errno::Eperm); }
            if !v.writable { return Err(Errno::Erofs); }
            // Skipping the checkpoint silently would report success for
            // durability the caller did not get.
            if v.cp_disabled { return Err(Errno::Einval); }
            want_write(c)
        }
        Req::FlushDevice { dev_num, .. } => {
            if !c.cap_sys_admin { return Err(Errno::Eperm); }
            if !v.writable { return Err(Errno::Erofs); }
            if v.cp_disabled { return Err(Errno::Einval); }
            // Emptying one device means moving its live blocks onto another,
            // so there has to be another; and the move is per segment, which
            // a multi-segment section cannot express.
            if !v.multi_device() || v.device_count - 1 <= *dev_num || v.large_section {
                return Err(Errno::Einval);
            }
            want_write(c)
        }

        Req::Defragment { start, len } => {
            if !c.cap_sys_admin { return Err(Errno::Eperm); }
            if !f.is_reg { return Err(Errno::Einval); }
            if !v.writable { return Err(Errno::Erofs); }
            if start % BLKSIZE != 0 || len % BLKSIZE != 0 { return Err(Errno::Einval); }
            let end = start.checked_add(*len).ok_or(Errno::Einval)?;
            if end / BLKSIZE > v.max_file_blocks { return Err(Errno::Einval); }
            want_write(c)
        }
        Req::MoveRange { .. } => {
            // Bytes leave one description and arrive in another, so the
            // source must be readable as well as writable.
            if !c.fmode_read || !c.fmode_write { return Err(Errno::Ebadf); }
            // A destination that is missing or read-only is a bad descriptor,
            // and that is decided BEFORE the mount's write reference; a
            // destination on another mount or another volume is a good
            // descriptor naming the wrong place, and that is decided after.
            if c.dst == DstFd::Unusable { return Err(Errno::Ebadf); }
            want_write(c)?;
            if c.dst == DstFd::Foreign { return Err(Errno::Exdev); }
            Ok(())
        }

        Req::GetFeatures | Req::GetPinFile | Req::GetDevAliasFile | Req::GetVersion
        | Req::GetFsLabel | Req::GetFlags | Req::FsGetXattr => Ok(()),

        Req::SetPinFile(pin) => {
            if !f.is_reg { return Err(Errno::Einval); }
            if !v.writable { return Err(Errno::Erofs); }
            // A device-alias file IS its pin; unpinning it would leave a file
            // whose blocks may move while something outside the filesystem
            // still addresses them.
            if *pin == 0 && f.device_alias { return Err(Errno::Eopnotsupp); }
            want_write(c)?;
            if f.atomic { return Err(Errno::Einval); }
            if *pin == 0 || f.pinned { return Ok(()); }
            // Pinning fixes the file's addresses, which only holds if it has
            // none yet.
            if f.has_blocks { return Err(Errno::Efbig); }
            if f.compressed { return Err(Errno::Eopnotsupp); }
            Ok(())
        }
        Req::IoPrio(level) => {
            if !f.is_reg || *level >= IOPRIO_MAX { return Err(Errno::Einval); }
            Ok(())
        }
        Req::PrecacheExtents => {
            if f.no_extent { return Err(Errno::Eopnotsupp); }
            Ok(())
        }
        Req::ResizeFs(_) => {
            if !c.cap_sys_admin { return Err(Errno::Eperm); }
            if !v.writable { return Err(Errno::Erofs); }
            Ok(())
        }

        Req::EnableVerity { .. } => {
            verity_enabled(v)?;
            if !c.fmode_write { return Err(Errno::Eacces); }
            // The tree is built by READING the file back, so a description
            // opened only for the command itself cannot serve.
            if !c.fmode_read { return Err(Errno::Ebadf); }
            if f.append_only { return Err(Errno::Eperm); }
            if f.is_dir { return Err(Errno::Eisdir); }
            if !f.is_reg { return Err(Errno::Einval); }
            want_write(c)?;
            // Nothing may be writing while the tree is built, or the tree
            // would attest bytes that changed under it.
            if c.writecount > 1 { return Err(Errno::Etxtbsy); }
            Ok(())
        }
        Req::MeasureVerity { .. } | Req::ReadVerityMetadata(_) => {
            verity_enabled(v)?;
            if !f.verity { return Err(Errno::Enodata); }
            Ok(())
        }

        Req::SetFsLabel(_) => {
            if !c.cap_sys_admin { return Err(Errno::Eperm); }
            want_write(c)
        }

        Req::GetCompressBlocks => {
            compression_enabled(v)?;
            if !f.compressed { return Err(Errno::Einval); }
            Ok(())
        }
        Req::ReleaseCompressBlocks => {
            compression_enabled(v)?;
            if !v.writable { return Err(Errno::Erofs); }
            want_write(c)?;
            // Releasing the saved blocks makes the file unwritable, so this
            // description must be the only writer — or, on a read-only
            // description, there must be no writer at all.
            let sole = if c.fmode_write { c.writecount == 1 } else { c.writecount == 0 };
            if !sole { return Err(Errno::Ebusy); }
            if !f.compressed || f.compress_released { return Err(Errno::Einval); }
            // Nothing was saved, so there is nothing to hand back, and
            // marking the file released would only make it unwritable.
            if f.compr_blocks == 0 { return Err(Errno::Eperm); }
            Ok(())
        }
        Req::ReserveCompressBlocks => {
            compression_enabled(v)?;
            if !v.writable { return Err(Errno::Erofs); }
            want_write(c)?;
            if !f.compressed || !f.compress_released { return Err(Errno::Einval); }
            Ok(())
        }
        Req::GetCompressOption => {
            compression_enabled(v)?;
            if !f.compressed { return Err(Errno::Enodata); }
            Ok(())
        }
        Req::SetCompressOption { algorithm, log_cluster_size } => {
            compression_enabled(v)?;
            if !c.fmode_write { return Err(Errno::Ebadf); }
            use crate::compress::algo::{COMPRESS_MAX, MAX_COMPRESS_LOG_SIZE,
                                        MIN_COMPRESS_LOG_SIZE};
            if *log_cluster_size < MIN_COMPRESS_LOG_SIZE
                || *log_cluster_size > MAX_COMPRESS_LOG_SIZE
                || *algorithm >= COMPRESS_MAX
            { return Err(Errno::Einval); }
            want_write(c)?;
            if !f.compressed { return Err(Errno::Einval); }
            // The cluster geometry decides what every existing block means,
            // so it can only change while the file has no blocks and nothing
            // is holding a mapping of them.
            if c.mmapped || c.dirty_pages > 0 { return Err(Errno::Ebusy); }
            if f.has_blocks { return Err(Errno::Efbig); }
            Ok(())
        }
        Req::DecompressFile | Req::CompressFile => {
            compression_enabled(v)?;
            // Rewriting clusters by hand only means anything when the mount
            // is not doing it on its own.
            if !v.compress_mode_user { return Err(Errno::Eopnotsupp); }
            if !c.fmode_write { return Err(Errno::Ebadf); }
            want_write(c)?;
            if !v.compress_backend_ready { return Err(Errno::Eopnotsupp); }
            if !f.compressed || f.compress_released { return Err(Errno::Einval); }
            Ok(())
        }

        Req::SecTrimFile { start, len, flags } => {
            if !c.fmode_write { return Err(Errno::Ebadf); }
            if *flags == 0 || flags & !TRIM_FILE_MASK != 0 || !f.is_reg {
                return Err(Errno::Einval);
            }
            if (flags & TRIM_FILE_DISCARD != 0 && !v.supports_discard)
                || (flags & TRIM_FILE_ZEROOUT != 0 && f.encrypted && v.multi_device())
            { return Err(Errno::Eopnotsupp); }
            want_write(c)?;
            if f.atomic || f.compressed { return Err(Errno::Einval); }
            // Which blocks the request comes to — and whether it names any at
            // all — is the trim's own arithmetic, asked here rather than
            // restated. A second copy of it can admit a request the trim then
            // refuses, or refuse one the trim would have carried out, and
            // neither shows up until a caller hits the difference.
            crate::sectrim::span::span(f.size, *start, *len,
                                       v.max_file_blocks.saturating_mul(BLKSIZE))?;
            Ok(())
        }

        Req::SetVersion(_) | Req::SetFlags(_) | Req::FsSetXattr(_) => {
            if !c.owner_or_capable { return Err(Errno::Eperm); }
            want_write(c)
        }
    }
}

/// Taking the mount's write reference, which a read-only mount refuses.
/// # C: O(1)
fn want_write(c: &Ctx) -> Result<(), Errno> {
    if c.mnt_writable { Ok(()) } else { Err(Errno::Erofs) }
}

/// # C: O(1)
fn encrypt_enabled(v: &VolFacts) -> Result<(), Errno> {
    if crate::features::has_encrypt(v.features) { Ok(()) } else { Err(Errno::Eopnotsupp) }
}

/// # C: O(1)
fn verity_enabled(v: &VolFacts) -> Result<(), Errno> {
    if crate::features::has_verity(v.features) { Ok(()) } else { Err(Errno::Eopnotsupp) }
}

/// # C: O(1)
fn compression_enabled(v: &VolFacts) -> Result<(), Errno> {
    if crate::features::has_compression(v.features) { Ok(()) } else { Err(Errno::Eopnotsupp) }
}

#[cfg(test)]
#[path = "../tests/ioctl/perm.rs"]
mod tests;
