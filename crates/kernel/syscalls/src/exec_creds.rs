// The credential transition execve(2) performs, as one pure function.
//
// Linux splits it across three call sites; the decision is one thing:
// * `bprm_fill_uid` — S_ISUID / S_ISGID honouring
// * `cap_bprm_creds_from_file`            — capability sets + `secureexec`
//   `get_file_caps` / `bprm_caps_from_vfs_caps` / `handle_privileged_root`
// * `begin_new_exec` — dumpability + `per_clear`
//
// UNGATED ON PURPOSE. The `059_execve/{x86_64,aarch64}.rs` slot files are
// `#![cfg(target_os = "oxide-kernel")]`, so a `#[cfg(test)] mod tests` placed
// inside one compiles out in silence while cargo prints "ok" — the privilege
// decision is the last thing in the tree that may go untested. Both arches call
// `transition`, so setuid handling and `AT_SECURE` cannot drift between them.

use syscall::errno::Errno;

/// Linux `bprm->cred` — the `struct cred` fields execve reads and rewrites.
/// `cap_bounding` is never altered by exec (Linux `cap_bset` survives), it is
/// carried here because `handle_privileged_root` and `bprm_caps_from_vfs_caps`
/// both compute against it.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskCreds {
    pub ruid: u32, pub euid: u32, pub suid: u32, pub fsuid: u32,
    pub rgid: u32, pub egid: u32, pub sgid: u32, pub fsgid: u32,
    pub cap_permitted: u64, pub cap_effective: u64, pub cap_inheritable: u64,
    pub cap_ambient: u64, pub cap_bounding: u64,
    pub securebits: u32,
}

/// Linux `struct cpu_vfs_cap_data` as `get_vfs_caps_from_disk` returns it from
/// the `security.capability` xattr. `present` is Linux's `has_fcap` (any
/// `VFS_CAP_REVISION_MASK` bit), `effective` is `VFS_CAP_FLAGS_EFFECTIVE`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FileCaps {
    pub present: bool,
    pub permitted: u64,
    pub inheritable: u64,
    pub effective: bool,
    /// Revision-3 `vfs_ns_cap_data.rootid` — the fs-namespace uid allowed to
    /// wield these caps. 0 for revision 1/2, which have no such field.
    pub rootid: u32,
}

/// Everything outside the caller's own credentials that the transition reads.
///
/// `mnt_may_suid` is Linux's `mnt_may_suid`: it gates BOTH the
/// setuid bits and file capabilities, which is why one flag covers both.
/// `file_uid_mapped` / `file_gid_mapped` are `vfsuid_has_mapping` /
/// `vfsgid_has_mapping` against the exec'ing task's user namespace.
pub struct ExecContext<'a> {
    pub old: TaskCreds,
    /// `inode->i_mode & 07777`, including `S_ISUID` / `S_ISGID` / `S_IXGRP`.
    pub file_mode: u16,
    /// `i_uid_into_vfsuid(idmap, inode)` / `i_gid_into_vfsgid`.
    pub file_uid: u32,
    pub file_gid: u32,
    pub mnt_may_suid: bool,
    pub file_uid_mapped: bool,
    pub file_gid_mapped: bool,
    /// `inode_permission(idmap, inode, MAY_EXEC)` succeeded — Linux re-checks
    /// it under `inode_lock` inside `bprm_fill_uid` after reloading the mode.
    pub may_exec: bool,
    pub file_caps: FileCaps,
    /// Linux `vfsuid_root_in_currentns(rootvfsuid)`: the xattr's revision-3
    /// `rootid` is uid 0 in the exec'ing task's user namespace. FALSE drops the
    /// file caps entirely (`get_vfs_caps_from_disk` returns `-ENODATA`), which
    /// is what stops a container writing `security.capability` for its own
    /// namespace-root and having the host honour it.
    pub file_caps_rootid_is_root: bool,
    /// `task_no_new_privs(current)`, i.e. `LSM_UNSAFE_NO_NEW_PRIVS`.
    pub no_new_privs: bool,
    /// `LSM_UNSAFE_SHARE`: another task shares this task's `fs_struct`.
    pub fs_shared: bool,
    /// Linux `ptracer_capable(current, new->user_ns)`. TRUE when there is no
    /// tracer at all (Linux: "An absent tracer adds no
    /// restrictions"), so an untraced exec is never downgraded by this clause.
    pub ptracer_capable: bool,
    /// `ns_capable(new->user_ns, CAP_SETUID)` evaluated against the CALLER's
    /// effective set — `bprm->cred` is not committed when Linux asks.
    pub can_setuid: bool,
    /// `make_kuid(new->user_ns, 0)`: the host uid that uid 0 maps to in the
    /// exec'ing task's user namespace. 0 in the initial namespace.
    pub root_uid: u32,
    /// Caller's supplementary groups, ascending — Linux `in_group_p` searches
    /// `current_cred()->group_info` and compares against `current_cred()->fsgid`.
    pub groups: &'a [u32],
    /// `would_dump`: `inode_permission(MAY_READ)` FAILED on the exec'd file, so
    /// Linux raises `BINPRM_FLAGS_ENFORCE_NONDUMP`.
    pub not_readable: bool,
    /// `/proc/sys/fs/suid_dumpable`.
    pub suid_dumpable: u8,
}

/// The committed result. `per_clear` is ANDNOT-ed into `task->personality`,
/// `secure_exec` becomes `AT_SECURE` and gates the `RLIMIT_STACK` reset.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExecTransition {
    pub new: TaskCreds,
    pub secure_exec: bool,
    pub per_clear: u32,
    pub dumpable: u8,
}

/// Linux `VFS_CAP_FLAGS_EFFECTIVE`.
pub const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x01;

/// Linux's `file_caps_enabled`, the `no_file_caps` boot parameter.
/// Default-on and never turned off here; named so the `get_file_caps` gate
/// reads the same as the kernel it mirrors.
const FILE_CAPS_ENABLED: bool = true;

/// Linux `in_group_p(grp)`: true when `grp` equals the
/// caller's `fsgid` or appears in its sorted supplementary list.
fn in_group_p(old: &TaskCreds, groups: &[u32], grp: u32) -> bool {
    grp == old.fsgid || groups.binary_search(&grp).is_ok()
}

/// Linux's `root_privileged()`: `!issecure(SECURE_NOROOT)`.
fn root_privileged(securebits: u32) -> bool {
    securebits & sched::securebits::SECBIT_NOROOT == 0
}

/// Compute the credentials a successful `execve` of this file installs.
///
/// `Err(EPERM)` is Linux `bprm_caps_from_vfs_caps` refusing an exec whose file
/// permitted set cannot be granted in full while the file's effective bit is
/// set — a legacy binary that cannot notice it is under-privileged must not run.
/// # C: O(ngroups)
pub fn transition(cx: &ExecContext<'_>) -> Result<ExecTransition, Errno> {
    let old = cx.old;
    let mut new = old;
    let mut per_clear = 0u32;

    // --- Linux's `bprm_fill_uid` --------------------------------------------
    // Every one of these guards is a suppression rule: a nosuid mount, a
    // no_new_privs task, a file whose exec bit vanished, and an owner with no
    // mapping in the caller's user namespace each leave the ids untouched.
    if cx.mnt_may_suid
        && !cx.no_new_privs
        && cx.file_mode & (vfs::S_ISUID | vfs::S_ISGID) != 0
        && cx.may_exec
        && cx.file_uid_mapped
        && cx.file_gid_mapped
    {
        if cx.file_mode & vfs::S_ISUID != 0 {
            per_clear |= sched::personality::PER_CLEAR_ON_SETID;
            new.euid = cx.file_uid;
        }
        // S_ISGID WITHOUT S_IXGRP is mandatory locking, not setgid.
        if cx.file_mode & (vfs::S_ISGID | vfs::S_IXGRP) == vfs::S_ISGID | vfs::S_IXGRP {
            per_clear |= sched::personality::PER_CLEAR_ON_SETID;
            new.egid = cx.file_gid;
        }
    }

    // --- Linux's `get_file_caps` --------------------------------------------
    // `cap_clear(bprm->cred->cap_permitted)` FIRST: exec starts from an empty
    // permitted set and everything below is a grant, never a carry-over.
    new.cap_permitted = 0;
    let mut effective = false;
    let mut has_fcap = false;
    if FILE_CAPS_ENABLED && cx.mnt_may_suid && cx.file_caps.present && cx.file_caps_rootid_is_root {
        // `bprm_caps_from_vfs_caps`: pP' = (X & fP) | (pI & fI); pA' added later.
        has_fcap = true;
        effective = cx.file_caps.effective;
        new.cap_permitted = (new.cap_bounding & cx.file_caps.permitted)
            | (new.cap_inheritable & cx.file_caps.inheritable);
        if effective && cx.file_caps.permitted & !new.cap_permitted != 0 {
            return Err(Errno::Eperm);
        }
    }

    // --- `handle_privileged_root` ------------------------------------------
    if root_privileged(new.securebits) {
        let is_eff_root  = new.euid == cx.root_uid;
        let is_real_root = new.ruid == cx.root_uid;
        // A setuid-root binary that ALSO carries file caps gets neither: the
        // file caps are the author's explicit statement of what it needs.
        let suid_root_with_fcap = has_fcap && is_eff_root && !is_real_root;
        if !suid_root_with_fcap {
            if is_eff_root || is_real_root {
                new.cap_permitted = old.cap_bounding | old.cap_inheritable;
            }
            if is_eff_root { effective = true; }
        }
    }

    let cap_gained = new.cap_permitted & !old.cap_permitted != 0;
    if cap_gained { per_clear |= sched::personality::PER_CLEAR_ON_SETID; }

    // --- the unsafe-exec downgrade -----------------------------------------
    // Linux: `(bprm->unsafe & ~LSM_UNSAFE_PTRACE) || !ptracer_capable(...)`.
    // Being ptraced alone does not downgrade — a tracer holding CAP_SYS_PTRACE
    // could have injected the code anyway — but no_new_privs or a shared
    // fs_struct does.
    let id_changed = new.euid != old.euid || !in_group_p(&old, cx.groups, new.egid);
    if (id_changed || cap_gained)
        && (cx.no_new_privs || cx.fs_shared || !cx.ptracer_capable)
    {
        if !cx.can_setuid || cx.no_new_privs {
            new.euid = new.ruid;
            new.egid = new.rgid;
        }
        new.cap_permitted &= old.cap_permitted;
    }

    // Saved and fs ids follow the effective ids across every exec.
    new.suid = new.euid; new.fsuid = new.euid;
    new.sgid = new.egid; new.fsgid = new.egid;

    // File caps or an id change cancel the ambient set: ambient is for
    // inheriting privilege across UNPRIVILEGED execs only.
    if has_fcap || id_changed { new.cap_ambient = 0; }

    // pP' |= pA';  pE' = fE ? pP' : pA'.
    new.cap_permitted |= new.cap_ambient;
    new.cap_effective = if effective { new.cap_permitted } else { new.cap_ambient };

    // `PR_SET_KEEPCAPS` does not survive exec; its LOCK bit does.
    new.securebits &= !sched::securebits::SECBIT_KEEP_CAPS;

    // --- `bprm->secureexec` -> AT_SECURE -----------------------------------
    // glibc keys LD_PRELOAD / LD_LIBRARY_PATH / LD_AUDIT / MALLOC_* / GCONV_PATH
    // and the `__libc_enable_secure` path off this single word, so it must be
    // right even where no privilege was actually gained.
    let secure_exec = id_changed
        || new.euid != old.ruid
        || new.egid != old.rgid
        || (new.ruid != cx.root_uid
            && (effective || new.cap_permitted & !new.cap_ambient != 0));

    // --- `begin_new_exec` dumpability --------------------------------------
    // Linux tests the NEW creds here and notes the check "only of current is
    // wrong, but userspace depends on it".
    let dumpable = if cx.not_readable || new.euid != new.ruid || new.egid != new.rgid {
        cx.suid_dumpable
    } else {
        sched::SUID_DUMP_USER
    };

    Ok(ExecTransition { new, secure_exec, per_clear, dumpable })
}

/// Decode a `security.capability` xattr value into [`FileCaps`]
/// (Linux `get_vfs_caps_from_disk`, the file-caps xattr wire layout):
///
/// ```text
///   magic_etc   u32   low 24 bits = VFS_CAP_REVISION_*, high 8 = flags
///   permitted   u32   low half
///   inheritable u32   low half
///   permitted   u32   high half        (revision 2+)
///   inheritable u32   high half        (revision 2+)
///   rootid      u32                    (revision 3)
/// ```
///
/// Note the INTERLEAVING: `struct vfs_cap_data` is `__le32 magic_etc` followed
/// by `data[VFS_CAP_U32]`, each element a `{permitted, inheritable}` PAIR — the
/// two halves of `permitted` are NOT adjacent. Reading it as two contiguous
/// u64s (permitted then inheritable) yields garbage for every capability above
/// bit 31, which is where CAP_AUDIT_* / CAP_BPF / CAP_PERFMON live.
/// # C: O(1)
pub fn decode_file_caps(xattr: &[u8]) -> Option<FileCaps> {
    const XATTR_CAPS_SZ_1: usize = 4 + 2 * 4;
    const XATTR_CAPS_SZ_2: usize = 4 + 2 * 2 * 4;
    const XATTR_CAPS_SZ_3: usize = XATTR_CAPS_SZ_2 + 4;
    const VFS_CAP_REVISION_MASK: u32 = 0xFF00_0000;
    const VFS_CAP_REVISION_1: u32 = 0x0100_0000;
    const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
    const VFS_CAP_REVISION_3: u32 = 0x0300_0000;
    // `CAP_VALID_MASK`: bits above CAP_LAST_CAP are not capabilities.
    let cap_mask = sched::Creds::CAP_FULL;

    if xattr.len() < XATTR_CAPS_SZ_1 { return None; }
    let word = |i: usize| -> u32 {
        u32::from_le_bytes([xattr[i * 4], xattr[i * 4 + 1], xattr[i * 4 + 2], xattr[i * 4 + 3]])
    };
    let magic_etc = word(0);
    let expect = match magic_etc & VFS_CAP_REVISION_MASK {
        VFS_CAP_REVISION_1 => XATTR_CAPS_SZ_1,
        VFS_CAP_REVISION_2 => XATTR_CAPS_SZ_2,
        VFS_CAP_REVISION_3 => XATTR_CAPS_SZ_3,
        _ => return None,
    };
    if xattr.len() != expect { return None; }
    let mut permitted = word(1) as u64;
    let mut inheritable = word(2) as u64;
    if expect > XATTR_CAPS_SZ_1 {
        permitted |= (word(3) as u64) << 32;
        inheritable |= (word(4) as u64) << 32;
    }
    Some(FileCaps {
        present: true,
        permitted: permitted & cap_mask,
        inheritable: inheritable & cap_mask,
        effective: magic_etc & VFS_CAP_FLAGS_EFFECTIVE != 0,
        rootid: if expect == XATTR_CAPS_SZ_3 { word(5) } else { 0 },
    })
}

#[cfg(test)]
mod tests;
