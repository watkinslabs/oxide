//! Carrying out an admitted request against a mounted volume.
//!
//! Admission has already run, so nothing here re-checks a permission: a
//! second copy of a ladder is a second answer to the same question, and the
//! two drift. What is left is the work, and the shape of the reply.
//!
//! A command whose volume-layer operation does not exist yet is reported as
//! [`Unbuilt`] rather than as an errno. That distinction is the point: an
//! errno would be indistinguishable from a refusal the contract defines, and
//! the gap would stop being visible the moment it was written. The variants
//! are enumerated so a test can assert exactly which commands are in that
//! state, and the list can only shrink on purpose.

use alloc::vec::Vec;

use sectors::SectorSource;
use syscall::errno::Errno;

use crate::crypto::KeyId;
use crate::volume::Volume;

use super::arg::{self, KeySpec};
use super::perm::{Ctx, DstFd};
use super::reply::Reply;
use super::req::Req;
use super::uapi::*;

/// A command whose admission is complete and whose volume-layer operation is
/// not built. Never an errno, so it can never be mistaken for a refusal the
/// contract defines.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Unbuilt {
    /// Emptying one device of a multi-device volume onto the others.
    FlushDevice,
}

/// The outcome of carrying out a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    Reply(Reply),
    NotBuilt(Unbuilt),
}

/// Carry out `r` against `v`. # C: command-dependent
pub fn exec<S: SectorSource>(v: &mut Volume<S>, ino: u32, c: &Ctx, r: &Req)
    -> Result<Outcome, Errno> {
    Ok(match r {
        Req::VolatileWrite => return Err(Errno::Eopnotsupp),

        // The handle-level ladder ran in admission, over the facts only a file
        // description carries; the ladder the volume applies here is over the
        // facts only the inode carries. Repeating either would be a second
        // answer to a question already answered.
        Req::StartAtomicWrite { replace } => {
            v.start_atomic_write(ino, *replace)?;
            Outcome::Reply(Reply::done())
        }
        Req::CommitAtomicWrite => { v.commit_atomic_write(ino)?; Outcome::Reply(Reply::done()) }
        Req::AbortAtomicWrite => { v.abort_atomic_write(ino)?; Outcome::Reply(Reply::done()) }
        // The bytes actually moved are written back over the caller's own
        // request, which is how a caller tells a range that was already one
        // run from one this had to rewrite.
        Req::Defragment { start, len } => {
            let moved = v.defragment_range(ino, *start, *len)?;
            let mut out = Vec::with_capacity(DEFRAGMENT_SIZE as usize);
            out.extend_from_slice(&start.to_le_bytes());
            out.extend_from_slice(&moved.to_le_bytes());
            Outcome::Reply(Reply::payload(out))
        }
        // The descriptor the request named was resolved by the layer that
        // owns descriptors, and admission has already refused every way it
        // could have been the wrong one.
        Req::MoveRange { pos_in, pos_out, len, .. } => {
            let DstFd::Ours(dst) = c.dst else { return Err(Errno::Exdev) };
            v.move_file_range(ino, *pos_in, dst, *pos_out, *len)?;
            Outcome::Reply(Reply::done())
        }
        Req::FlushDevice { .. } => Outcome::NotBuilt(Unbuilt::FlushDevice),
        // Both report the blocks they moved through the caller's own argument
        // word, which is the count a caller distributing images checks against
        // what it expected to get back.
        Req::ReleaseCompressBlocks =>
            Outcome::Reply(Reply::u64(v.release_compress_blocks(ino)?)),
        Req::ReserveCompressBlocks =>
            Outcome::Reply(Reply::u64(v.reserve_compress_blocks(ino)?)),
        Req::SecTrimFile { start, len, flags } => {
            v.sec_trim_file(ino, *start, *len, *flags)?;
            Outcome::Reply(Reply::done())
        }
        // The count of clusters rewritten is this build's own; the command
        // reports success and nothing else, as the caller's argument word is
        // unused in both directions.
        Req::CompressFile => { v.compress_file(ino)?; Outcome::Reply(Reply::done()) }
        Req::DecompressFile => { v.decompress_file(ino)?; Outcome::Reply(Reply::done()) }
        Req::ResizeFs(blocks) => { v.resize_fs(*blocks)?; Outcome::Reply(Reply::done()) }

        Req::Shutdown(mode) => {
            // Every mode but the last two takes the volume's state to the
            // medium first; the ones that do not are what a caller reaches
            // for when the medium is what it no longer trusts.
            match *mode {
                GOING_DOWN_FULLSYNC | GOING_DOWN_METASYNC | GOING_DOWN_METAFLUSH => {
                    if v.writable() { v.commit()?; }
                }
                _ => {}
            }
            Outcome::Reply(Reply::done())
        }

        Req::Fitrim { start, len, minlen } => {
            let (trimmed, granularity) = v.trim_free_space(*start, *len, *minlen)?;
            // The granularity actually used is reported back, because a
            // caller that asked for a smaller one got a larger.
            let mut out = Vec::with_capacity(FSTRIM_RANGE_SIZE as usize);
            out.extend_from_slice(&start.to_le_bytes());
            out.extend_from_slice(&trimmed.to_le_bytes());
            out.extend_from_slice(&granularity.to_le_bytes());
            Outcome::Reply(Reply::payload(out))
        }

        Req::Gc { sync } => {
            // A synchronous collection is asked to free a section and to
            // report if it could not; a background one takes whatever one
            // pass gives.
            let freed = if *sync { v.collect(1)? } else { v.gc_background()?.map_or(0, |_| 1) };
            if *sync && freed == 0 { return Err(Errno::Eagain); }
            Outcome::Reply(Reply::done())
        }
        Req::GcRange { start, len, sync } => {
            let per = u64::from(crate::uapi::BLKS_PER_SEG)
                * u64::from(v.super_block().segs_per_sec);
            let end = start + len;
            let mut at = *start;
            let mut freed = 0u32;
            while at <= end {
                let segno = ((at - v.super_block().main_blkaddr as u64)
                    / u64::from(crate::uapi::BLKS_PER_SEG)) as u32;
                match v.gc_section(segno) {
                    Ok(n) => freed += n,
                    // A section nothing could be taken from stops a
                    // best-effort pass and fails an exhaustive one.
                    Err(Errno::Eagain) if !*sync => break,
                    Err(e) => return Err(e),
                }
                at += per;
            }
            if *sync && freed == 0 { return Err(Errno::Eagain); }
            Outcome::Reply(Reply::done())
        }
        Req::WriteCheckpoint => { v.commit()?; Outcome::Reply(Reply::done()) }

        Req::GetFeatures => Outcome::Reply(Reply::u32(v.ioctl_features())),
        Req::GetPinFile => {
            // The value is the count of times the cleaner failed to move this
            // file, which is mount state this build does not keep, so a
            // freshly mounted inode reports the same zero it would there.
            let _ = v.is_pinned(ino)?;
            Outcome::Reply(Reply::u32(0))
        }
        Req::SetPinFile(pin) => { v.set_pinned(ino, *pin != 0)?; Outcome::Reply(Reply::u32(0)) }
        // A volume carrying the device-alias feature is refused at mount, so
        // no file on a mounted volume is one.
        Req::GetDevAliasFile => Outcome::Reply(Reply::u32(0)),
        Req::IoPrio(_) => Outcome::Reply(Reply::done()),
        Req::PrecacheExtents => {
            let inode = v.read_inode(ino)?;
            v.precache_extents(&inode, ino)?;
            Outcome::Reply(Reply::done())
        }

        Req::GetVersion => Outcome::Reply(Reply::u32(v.read_inode(ino)?.generation)),
        Req::SetVersion(gen) => {
            v.set_generation(ino, *gen)?;
            Outcome::Reply(Reply::done())
        }
        Req::GetFsLabel => Outcome::Reply(Reply::payload(v.label_buffer())),
        Req::SetFsLabel(bytes) => {
            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            let name = core::str::from_utf8(&bytes[..end]).map_err(|_| Errno::Einval)?;
            v.set_label(name)?;
            Outcome::Reply(Reply::done())
        }

        Req::GetCompressBlocks => Outcome::Reply(Reply::u64(v.compress_blocks(ino)?)),
        Req::GetCompressOption => {
            let (a, l) = v.compress_option(ino)?;
            Outcome::Reply(Reply::payload(alloc::vec![a, l]))
        }
        Req::SetCompressOption { algorithm, log_cluster_size } => {
            v.set_compress_option(ino, *algorithm, *log_cluster_size)?;
            Outcome::Reply(Reply::done())
        }

        Req::GetEncryptionPwsalt => {
            let salt = v.encryption_pwsalt(fresh_salt(v, ino))?;
            Outcome::Reply(Reply::payload(salt.to_vec()))
        }
        Req::GetEncryptionNonce => {
            let inode = v.read_inode(ino)?;
            let ctx = v.crypt_context(&inode, ino)?.ok_or(Errno::Enodata)?;
            Outcome::Reply(Reply::payload(ctx.nonce.to_vec()))
        }
        Req::AddEncryptionKey { key, raw } => {
            if key.flags & ADD_KEY_FLAG_HW_WRAPPED != 0 { return Err(Errno::Eopnotsupp); }
            // A key named from elsewhere needs a provisioning keyring, which
            // this build does not have, so no identifier it could name is
            // present.
            if key.key_id != 0 { return Err(Errno::Enokey); }
            let id = match key.spec {
                KeySpec::Descriptor(d) => v.add_encryption_key_by_descriptor(d, raw)?,
                KeySpec::Identifier(_) => v.add_encryption_key(raw)?,
            };
            // The identifier is DERIVED from the key, so the one the caller
            // supplied is replaced by the one the key actually has — that is
            // the whole point of the newer naming scheme.
            let mut out = alloc::vec![0u8; ADD_KEY_ARG_SIZE as usize];
            arg::put_key_spec(&mut out, ADD_KEY_SPECIFIER, &spec_of(&id))?;
            arg::put_u32(&mut out, ADD_KEY_RAW_SIZE, key.raw_size)?;
            Outcome::Reply(Reply::payload(out))
        }
        Req::RemoveEncryptionKey { spec, .. } => {
            let id = id_of(spec);
            if !v.remove_encryption_key(&id) { return Err(Errno::Enokey); }
            let mut out = alloc::vec![0u8; REMOVE_KEY_ARG_SIZE as usize];
            arg::put_key_spec(&mut out, REMOVE_KEY_SPECIFIER, spec)?;
            // Nothing holds a key open here, so no removal is ever partial
            // and no status flag is raised.
            Outcome::Reply(Reply::payload(out))
        }
        Req::GetEncryptionKeyStatus { spec } => {
            let present = v.holds_encryption_key(&id_of(spec));
            let mut out = alloc::vec![0u8; KEY_STATUS_ARG_SIZE as usize];
            arg::put_key_spec(&mut out, KEY_STATUS_SPECIFIER, spec)?;
            arg::put_u32(&mut out, KEY_STATUS_STATUS,
                         if present { KEY_STATUS_PRESENT } else { KEY_STATUS_ABSENT })?;
            if present {
                // Keys are held per mount rather than per user here, so the
                // single holder is whoever is asking.
                arg::put_u32(&mut out, KEY_STATUS_FLAGS, KEY_STATUS_FLAG_ADDED_BY_SELF)?;
                arg::put_u32(&mut out, KEY_STATUS_USER_COUNT, 1)?;
            }
            Outcome::Reply(Reply::payload(out))
        }
        Req::SetEncryptionPolicy(bytes) => {
            v.set_encryption_policy(ino, bytes)?;
            Outcome::Reply(Reply::done())
        }
        Req::GetEncryptionPolicy => {
            let inode = v.read_inode(ino)?;
            let ctx = v.crypt_context(&inode, ino)?.ok_or(Errno::Enodata)?;
            let out = super::policy::encode_v1(&ctx.policy).ok_or(Errno::Einval)?;
            Outcome::Reply(Reply::payload(out))
        }
        Req::GetEncryptionPolicyEx { capacity } => {
            let inode = v.read_inode(ino)?;
            let ctx = v.crypt_context(&inode, ino)?.ok_or(Errno::Enodata)?;
            let body = super::policy::encode_wire(&ctx.policy);
            if body.len() as u64 > *capacity { return Err(Errno::Eoverflow); }
            let mut out = alloc::vec![0u8; POLICY_EX_ARG_SIZE as usize];
            arg::put_u64(&mut out, POLICY_EX_SIZE_FIELD, body.len() as u64)?;
            out[POLICY_EX_POLICY..POLICY_EX_POLICY + body.len()].copy_from_slice(&body);
            Outcome::Reply(Reply::payload(out))
        }

        Req::EnableVerity { head, salt, sig } => {
            let log_bs = head.block_size.trailing_zeros() as u8;
            let alg = u8::try_from(head.hash_algorithm).map_err(|_| Errno::Einval)?;
            v.enable_verity_signed(ino, alg, log_bs, salt, sig)?;
            Outcome::Reply(Reply::done())
        }
        Req::MeasureVerity { capacity } => {
            let inode = v.read_inode(ino)?;
            let info = v.verity_info(&inode, ino)?;
            let digest = info.file_digest.clone();
            // The caller's buffer decides whether the answer fits, and a
            // short one is told so rather than given a truncated digest that
            // would compare unequal to every genuine one.
            if (*capacity as usize) < digest.len() { return Err(Errno::Eoverflow); }
            let mut head = alloc::vec![0u8; VERITY_DIGEST_HEAD_SIZE as usize];
            arg::put_u16(&mut head, VD_ALGORITHM, u16::from(info.params.hash_alg))?;
            arg::put_u16(&mut head, VD_SIZE, digest.len() as u16)?;
            Outcome::Reply(Reply::payload(head).with_indirect(digest))
        }
        Req::ReadVerityMetadata(m) => {
            let bytes = v.verity_metadata(ino, m.kind, m.offset, m.length)?;
            let n = bytes.len() as i64;
            Outcome::Reply(Reply { payload: None, indirect: Some(bytes), value: n })
        }

        // Owned by the generic and typed stages, which reach the same volume
        // operations through their own entry points.
        Req::GetFlags | Req::SetFlags(_) | Req::FsGetXattr | Req::FsSetXattr(_) =>
            return Err(Errno::Enotty),
    })
}

/// The name a policy refers to a key by, for a key a command named.
/// # C: O(1)
fn id_of(k: &KeySpec) -> KeyId {
    match k {
        KeySpec::Descriptor(d) => KeyId::Descriptor(*d),
        KeySpec::Identifier(i) => KeyId::Identifier(*i),
    }
}

/// The wire form of a key name. # C: O(1)
fn spec_of(k: &KeyId) -> KeySpec {
    match k {
        KeyId::Descriptor(d) => KeySpec::Descriptor(*d),
        KeyId::Identifier(i) => KeySpec::Identifier(*i),
    }
}

/// A salt for a volume that has none yet.
///
/// Derived from what the volume already carries rather than drawn from a
/// generator, because this crate has no medium-independent source and a
/// constant salt would make every volume's derived keys the same.
/// # C: O(1)
fn fresh_salt<S: SectorSource>(v: &Volume<S>, ino: u32) -> [u8; 16] {
    let mut s = [0u8; 16];
    let uuid = &v.super_block().uuid;
    for (i, b) in s.iter_mut().enumerate() {
        *b = uuid.get(i).copied().unwrap_or(0) ^ (ino.rotate_left(i as u32 * 3) as u8);
    }
    s
}

#[cfg(test)]
#[path = "../tests/ioctl/exec.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/ioctl/atomic.rs"]
mod atomic_tests;

#[cfg(test)]
#[path = "../tests/ioctl/compress_blocks.rs"]
mod compress_blocks_tests;

#[cfg(test)]
#[path = "../tests/ioctl/rewrite.rs"]
mod rewrite_tests;

#[cfg(test)]
#[path = "../tests/ioctl/resize.rs"]
mod resize_tests;

#[cfg(test)]
#[path = "../tests/ioctl/rangeops.rs"]
mod rangeops_tests;
