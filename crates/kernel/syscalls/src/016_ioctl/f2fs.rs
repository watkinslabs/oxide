#![cfg(target_os = "oxide-kernel")]

//! The usercopy half of this filesystem's own ioctl handler.
//!
//! Everything a command MEANS lives in `f2fs::ioctl`: which commands exist,
//! how far each argument travels and in which direction, what the bytes
//! decode to, who may send one, and what carrying it out does. This file moves
//! bytes between the caller and that surface, and decides nothing — which is
//! the only reason it may be target-gated, since a decision made here could
//! not be tested at all.
//!
//! It runs AFTER the generic stage and after the typed file-operations stage,
//! and answers only what neither of those owns (`f2fs::ioctl::spec::owns`), so
//! no stage shadows another. It recognises its own files by the backend state
//! their inode carries, so a foreign inode falls through untouched rather than
//! being told no such operation on another filesystem's behalf.

use alloc::sync::Arc;
use alloc::vec;

use syscall::errno::Errno;

use f2fs::ioctl::{self, spec, Answer, Ctx, DstFd, Extra, Indirect, Payload};

use crate::ioctl_user as user;
use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

/// `f2fs_ioctl`.
///
/// `None` says this is not this filesystem's file, or not this handler's
/// command, and the caller carries on down its own chain.
/// # C: command-dependent
pub(super) fn handle_f2fs_ioctl(cur: &sched::Task, file: &Arc<vfs::File>, fdt: &vfs::FdTable,
                                req: u64, arg: u64) -> Option<i64> {
    let cmd = req as u32;
    let s = spec::spec(cmd)?;
    if !spec::owns(cmd) { return None; }
    if !ioctl::vfs::is_f2fs(file.inode()) { return None; }

    let n = spec::payload_len(cmd) as usize;
    let mut payload = vec![0u8; n];
    if let Err(rv) = fetch_payload(s.payload, arg, &mut payload) { return Some(rv); }
    let mut extra = Extra::default();
    if let Err(rv) = fetch_indirect(s.indirect, arg, &mut payload, &mut extra) {
        return Some(rv);
    }
    let c = build_ctx(cur, file, fdt, cmd, &payload);

    // Everything above moved bytes; nothing above decided anything.
    let reply = match ioctl::vfs::raw(file, cmd, &payload, &extra, &c)? {
        Ok(Answer::Done(r)) => r,
        // Admitted, and the volume operation behind it does not exist. Told to
        // the caller as the one errno that means "this filesystem cannot do
        // this", never as one of the contract's own refusals — those mean the
        // request was wrong, and this one says it was not.
        Ok(Answer::NotBuilt(_)) => return Some(-(Errno::Eopnotsupp.as_i32() as i64)),
        Err(e) => return Some(-(e as i64)),
    };
    Some(put_reply(s.indirect, arg, &payload, &reply))
}

/// Bring the fixed argument in, and make sure an outward one can be written
/// BEFORE the command runs.
///
/// A reply the caller cannot receive must not cost the caller the operation:
/// the check belongs ahead of the work, which is where the reference's own
/// `copy_from_user`/`copy_to_user` pairing puts it for the commands that both
/// read and write.
/// # C: O(payload bytes)
fn fetch_payload(p: Payload, arg: u64, buf: &mut [u8]) -> Result<(), i64> {
    let n = buf.len() as u64;
    match p {
        Payload::None => Ok(()),
        Payload::In(_) => {
            validate_user_buf_readable(arg, n, 1)?;
            user::get_into(arg, buf)
        }
        Payload::Out(_) => validate_user_buf_writable(arg, n, 1),
        Payload::InOut(_) => {
            validate_user_buf_readable(arg, n, 1)?;
            validate_user_buf_writable(arg, n, 1)?;
            user::get_into(arg, buf)
        }
    }
}

/// Bring in whatever the fixed argument named through a pointer of its own.
/// # C: O(bytes named)
fn fetch_indirect(i: Indirect, arg: u64, payload: &mut alloc::vec::Vec<u8>, extra: &mut Extra)
    -> Result<(), i64> {
    use ioctl::uapi::*;
    match i {
        Indirect::None | Indirect::VerityMeasure | Indirect::VerityReadMetadata => Ok(()),
        Indirect::AddKeyRaw => {
            let raw = le32(payload, ADD_KEY_RAW_SIZE) as usize;
            // The key rides past the fixed part, whose own field says how much
            // of it there is; a bound is applied here because that field is
            // the caller's and the allocation is ours.
            if raw > MAX_RAW_KEY { return Err(-(Errno::Einval.as_i32() as i64)); }
            if raw == 0 { return Ok(()); }
            let at = arg.wrapping_add(ADD_KEY_RAW as u64);
            validate_user_buf_readable(at, raw as u64, 1)?;
            extra.first = vec![0u8; raw];
            user::get_into(at, &mut extra.first)
        }
        Indirect::VerityEnable => {
            let salt = le32(payload, VE_SALT_SIZE) as usize;
            let sig = le32(payload, VE_SIG_SIZE) as usize;
            if salt > 0 {
                let at = le64(payload, VE_SALT_PTR);
                validate_user_buf_readable(at, salt as u64, 1)?;
                extra.first = vec![0u8; salt];
                user::get_into(at, &mut extra.first)?;
            }
            if sig > 0 {
                let at = le64(payload, VE_SIG_PTR);
                validate_user_buf_readable(at, sig as u64, 1)?;
                extra.second = vec![0u8; sig];
                user::get_into(at, &mut extra.second)?;
            }
            Ok(())
        }
        Indirect::PolicyIn => {
            // The version byte decides the length. The fixed part is the
            // SHORTER version, so it is always readable; reading the longer one
            // unconditionally would refuse every caller still sending the
            // short form.
            if payload.first().copied() != Some(f2fs::crypto::uapi::POLICY_V2) { return Ok(()); }
            let want = POLICY_V2_SIZE as usize;
            validate_user_buf_readable(arg, want as u64, 1)?;
            payload.resize(want, 0);
            user::get_into(arg, payload)
        }
        Indirect::LabelString => {
            // A string, not a buffer: only as far as the terminator has to be
            // readable, or a caller passing a short label at the end of a
            // mapping is refused for bytes it never claimed to have.
            let mut buf = vec![0u8; FSLABEL_MAX as usize];
            let mut got = 0usize;
            while got < buf.len() {
                let at = arg.wrapping_add(got as u64);
                if validate_user_buf_readable(at, 1, 1).is_err() { break; }
                match user::get_u8(at) {
                    Ok(0) => break,
                    Ok(b) => { buf[got] = b; got += 1; }
                    Err(rv) => return Err(rv),
                }
            }
            buf.truncate(got);
            extra.first = buf;
            Ok(())
        }
    }
}

/// Write the reply back through whichever of its channels carry anything, and
/// give the call's own result. # C: O(reply bytes)
fn put_reply(i: Indirect, arg: u64, payload: &[u8], reply: &ioctl::Reply) -> i64 {
    if let Some(bytes) = reply.payload.as_deref() {
        if let Err(rv) = validate_user_buf_writable(arg, bytes.len() as u64, 1) { return rv; }
        if let Err(rv) = user::put_bytes(arg, bytes) { return rv; }
    }
    if let Some(bytes) = reply.indirect.as_deref() {
        // WHERE those bytes go is the surface's own answer, not this layer's:
        // a guess here is a write to whatever the caller happens to have at
        // the guessed address.
        let Some(at) = spec::indirect_out(i, arg, payload) else {
            return -(Errno::Einval.as_i32() as i64);
        };
        if !bytes.is_empty() {
            if let Err(rv) = validate_user_buf_writable(at, bytes.len() as u64, 1) { return rv; }
            if let Err(rv) = user::put_bytes(at, bytes) { return rv; }
        }
    }
    reply.value
}

/// The caller and its open description, as the admission ladder reads them.
///
/// Every field is the fact the ladder names, taken from whatever this kernel
/// keeps it in — the ladder's contract is the FACT, not the accessor.
/// # C: O(1)
fn build_ctx(cur: &sched::Task, file: &Arc<vfs::File>, fdt: &vfs::FdTable, cmd: u32,
             payload: &[u8]) -> Ctx {
    let mode = file.f_mode();
    let inode = file.inode();
    Ctx {
        cap_sys_admin: cur.has_cap(sched::cap::SYS_ADMIN),
        fmode_read: mode.contains(vfs::Fmode::READ),
        fmode_write: mode.contains(vfs::Fmode::WRITE),
        o_direct: file.flags().contains(vfs::OpenFlags::O_DIRECT),
        owner_or_capable: vfs::inode::inode_owner_or_capable(&vfs::mount::idmap_for(file.mnt_id()),
                                                      inode, &current_cred()),
        // Taking the reference is what a write-bearing command needs, and a
        // read-only mount is what refuses it. Dropped again immediately: this
        // asks whether the mount would allow the write, and the operation
        // itself runs under the volume's own lock.
        mnt_writable: mount_writable(file),
        // Negative is a deny-write reference, which is no writers at all.
        writecount: inode.writecount().max(0) as u32,
        // Nothing in this build keeps a per-inode count of dirty pages: this
        // filesystem writes through its volume rather than through a page
        // cache, so there is never a page of it dirty for a command to wait
        // on.
        dirty_pages: 0,
        mmapped: inode.file_rmap().live_target_count() > 0,
        dst: dst_of(file, fdt, cmd, payload),
    }
}

/// Whether the mount would take a write reference. # C: O(1)
fn mount_writable(file: &Arc<vfs::File>) -> bool {
    match file.vfsmount() {
        Some(mnt) => {
            let ok = vfs::mount::mnt_want_write(&mnt).is_ok();
            if ok { vfs::mount::mnt_drop_write(&mnt); }
            ok && !mnt.sb().is_readonly()
        }
        // An anonymous file has no mount to refuse the write.
        None => true,
    }
}

/// The descriptor a move names, resolved.
///
/// Only for the one command that names one; every other command is handed the
/// unusable answer, which none of them reads.
/// # C: O(1)
fn dst_of(file: &Arc<vfs::File>, fdt: &vfs::FdTable, cmd: u32, payload: &[u8]) -> DstFd {
    if cmd != ioctl::uapi::MOVE_RANGE { return DstFd::Unusable; }
    if payload.len() < 4 { return DstFd::Unusable; }
    let dst = fdt.get(le32(payload, 0) as i32).ok();
    ioctl::vfs::resolve_dst(file, dst.as_deref())
}

#[cfg(not(test))]
fn current_cred() -> vfs::Cred { crate::pathresolve::current_cred() }

#[cfg(test)]
fn current_cred() -> vfs::Cred { vfs::Cred::root() }

/// # C: O(1)
fn le32(b: &[u8], at: usize) -> u32 {
    let mut w = [0u8; 4];
    w.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(w)
}

/// # C: O(1)
fn le64(b: &[u8], at: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(w)
}
