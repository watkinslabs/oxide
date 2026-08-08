// fcntl lease / delegation commands: F_SETLEASE, F_SETDELEG and the
// `struct delegation` fetch, split out of `072_fcntl.rs` for the file cap.
//
// ABI shim only (`docs/53`): every decision — the validation ladder, the
// flavour, the admission rules — belongs to `vfs::file`'s lease policy and the
// ungated `crate::fcntl_deleg` wire form, both unit-tested there.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

use crate::fcntl_deleg;
use crate::userbuf::validate_user_buf;

/// `f_modown`'s `fown->uid` — the REAL uid, not the fsuid the VFS `Cred`
/// carries for DAC. # C: O(1)
pub(crate) fn fowner_uid() -> u32 {
    use core::sync::atomic::Ordering;
    sched::live::current().map(|t| t.creds.ruid.load(Ordering::Acquire)).unwrap_or(0)
}

/// `f_modown`'s `fown->euid`. # C: O(1)
pub(crate) fn fowner_euid() -> u32 {
    use core::sync::atomic::Ordering;
    sched::live::current().map(|t| t.creds.euid.load(Ordering::Acquire)).unwrap_or(0)
}

/// Read + validate the caller's `struct delegation`. `Err` is the negative
/// errno to return: `EFAULT` for an unusable pointer, `EINVAL` for a non-zero
/// reserved field. # C: O(1)
pub(crate) fn read_delegation(arg: u64) -> Result<fcntl_deleg::Delegation, i64> {
    use crate::fcntl_deleg::{DELEGATION_ALIGN, DELEGATION_BYTES};
    if let Err(rv) = validate_user_buf(arg, DELEGATION_BYTES as u64, DELEGATION_ALIGN) {
        return Err(rv);
    }
    let mut b = [0u8; DELEGATION_BYTES];
    // SAFETY: arg validated for DELEGATION_BYTES below USER_VA_END; CPL=0 reads through caller's AS.
    unsafe {
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = core::ptr::read_volatile((arg + i as u64) as *const u8);
        }
    }
    fcntl_deleg::decode_delegation(&b).map_err(|e| -(e.as_i32() as i64))
}

/// Write the answer to a get-delegation query back into the caller's
/// `struct delegation`. # C: O(1)
pub(crate) fn write_delegation(arg: u64, d_type: i32) {
    let out = fcntl_deleg::encode_delegation(d_type);
    // SAFETY: arg was validated for DELEGATION_BYTES below USER_VA_END by
    // `read_delegation` on this same call; CPL=0 writes through the caller's AS.
    unsafe {
        for (i, b) in out.iter().enumerate() {
            core::ptr::write_volatile((arg + i as u64) as *mut u8, *b);
        }
    }
}

/// `F_SETLEASE` / `F_SETDELEG` — one implementation, because a lease and a
/// delegation are one object with two commands over it. The ladder deciding
/// whether the request is legal is the VFS lease policy; what is left here is
/// the ABI wrapper plus the two admission tests that need the live registry:
/// no conflicting second holder, and no conflicting open.
///
/// A holder must be reachable by the break signal, so a descriptor with no
/// `f_owner` defaults to the calling process and the delivery hook is
/// installed — a lease whose break nobody hears can never be broken.
/// # C: O(N_leases)
pub(crate) fn set_lease(
    cur: &sched::Task,
    file: &alloc::sync::Arc<vfs::File>,
    kind: vfs::file::LeaseKind,
    ty: i32,
) -> i64 {
    use core::sync::atomic::Ordering;
    use vfs::file::owner_type::F_OWNER_PID;
    /// Release form of both commands.
    const F_UNLCK: i32 = 2;
    let inode = file.inode();
    let ftype = inode.file_type();
    let target = vfs::file::LeaseTarget {
        is_dir: matches!(ftype, vfs::FileType::Directory),
        is_reg: matches!(ftype, vfs::FileType::Regular),
    };
    let cred = crate::pathresolve::current_cred();
    let may = vfs::file::may_lease(
        inode.uid().unwrap_or(0), cred.uid, cur.has_cap(sched::cap::LEASE));
    if let Err(e) = vfs::file::setlease_check(kind, target, may, ty) {
        return -(e as i64);
    }
    if ty == F_UNLCK {
        file.set_lease_of(vfs::file::FL_NONE, F_UNLCK);
        vfs::file::lease_unregister(file);
        return 0;
    }
    // EAGAIN, not EINVAL: both refusals are "not right now" — another
    // description holds a lease on this file, or the file is open in a way the
    // requested lease cannot coexist with.
    if vfs::file::add_lease_conflict(file, ty) {
        return -(Errno::Eagain.as_i32() as i64);
    }
    if vfs::file::open_conflicts(ty, inode.writecount(),
                                 file.f_mode().contains(vfs::Fmode::WRITE)) {
        return -(Errno::Eagain.as_i32() as i64);
    }
    if file.owner.load(Ordering::Acquire) == 0 {
        let tgid = cur.tgid.load(Ordering::Acquire) as i32;
        file.f_setown(tgid, F_OWNER_PID, fowner_uid(), fowner_euid());
    }
    sched::live::sigpend::install_sigio_hook();
    file.set_lease_of(kind.flavour(), ty);
    vfs::file::lease_register(file);
    0
}
