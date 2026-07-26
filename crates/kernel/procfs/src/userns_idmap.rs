// Linux `/proc/<pid>/{uid_map,gid_map,setgroups}` — real views over the
// canonical `user-namespace` id-map engine (`docs/26§2` invariant 6,
// `docs/26§3.6`). Replaces the former `SysctlInode` fake that seeded every
// namespace with a fabricated full-range identity string and accepted any
// write verbatim without translation.

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use namespace_identity::NamespaceRef;
use nscg::user_ns::{self, IdMapExtent, IdMapKind, SetgroupsPolicy, UserNsError};
use vfs::{FileCred, KResult, VfsError};

#[cfg(target_os = "oxide-kernel")]
use vfs::{default_inode_ops, mk_mode, File, FileOps, FileType, Inode, InodeBuilder, InodeRef};

#[cfg(target_os = "oxide-kernel")]
const FILE_MODE: u16 = 0o644;
const PAGE_SIZE: usize = 4096;
/// `write(2)` on a Linux `setgroups` file accepts only "allow"/"deny" plus
/// an optional trailing newline (Linux `proc_setgroups_write` `kbuf[8]`).
const SETGROUPS_BUF_MAX: usize = 8;

fn error(err: UserNsError) -> VfsError {
    match err {
        UserNsError::WrongKind => VfsError::Einval,
        UserNsError::InitialOwner | UserNsError::NoParent | UserNsError::AlreadyPopulated
        | UserNsError::UnprivilegedNotOwnId | UserNsError::SetgroupsMustDenyFirst
        | UserNsError::SetgroupsLockedAfterGidMap => VfsError::Eperm,
        UserNsError::EmptyExtents | UserNsError::TooManyExtents | UserNsError::ZeroCount
        | UserNsError::RangeOverflow | UserNsError::Overlap => VfsError::Einval,
    }
}

#[cfg(target_os = "oxide-kernel")]
fn target_owner(task: &sched::Task) -> KResult<NamespaceRef> {
    task.namespace_owner(namespace_identity::NamespaceKind::User).ok_or(VfsError::Esrch)
}

/// Linux seq_show format: `"%10u %10u %10u\n"` per extent. # C: O(extents)
fn body_map(owner: &NamespaceRef, kind: IdMapKind) -> KResult<Vec<u8>> {
    let extents = user_ns::snapshot_map(owner, kind).map_err(error)?;
    let mut out = Vec::new();
    for extent in extents {
        out.extend_from_slice(
            format!("{:>10} {:>10} {:>10}\n", extent.ns_id, extent.host_id, extent.count)
                .as_bytes());
    }
    Ok(out)
}

fn body_setgroups(owner: &NamespaceRef) -> KResult<Vec<u8>> {
    Ok(match user_ns::setgroups_policy(owner).map_err(error)? {
        SetgroupsPolicy::Allow => b"allow\n".to_vec(),
        SetgroupsPolicy::Deny => b"deny\n".to_vec(),
    })
}

fn parse_u32(value: &str) -> KResult<u32> {
    value.parse::<u32>().map_err(|_| VfsError::Einval)
}

/// Parse the entire write(2) buffer as one batch of `<ns_id> <host_id>
/// <count>` lines (Linux `map_write` parses+validates the whole buffer
/// before committing any of it — no partial-line consumption). # C: O(lines)
fn parse_extents(src: &[u8]) -> KResult<Vec<IdMapExtent>> {
    if src.is_empty() || src.len() >= PAGE_SIZE { return Err(VfsError::Einval); }
    let text = core::str::from_utf8(src).map_err(|_| VfsError::Einval)?;
    let mut extents = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.len() != 3 { return Err(VfsError::Einval); }
        extents.push(IdMapExtent {
            ns_id: parse_u32(fields[0])?, host_id: parse_u32(fields[1])?,
            count: parse_u32(fields[2])?,
        });
    }
    if extents.is_empty() { return Err(VfsError::Einval); }
    Ok(extents)
}

fn parse_setgroups(src: &[u8]) -> KResult<SetgroupsPolicy> {
    if src.len() >= SETGROUPS_BUF_MAX { return Err(VfsError::Einval); }
    let text = core::str::from_utf8(src).map_err(|_| VfsError::Einval)?.trim_end_matches('\n');
    match text {
        "allow" => Ok(SetgroupsPolicy::Allow),
        "deny" => Ok(SetgroupsPolicy::Deny),
        _ => Err(VfsError::Einval),
    }
}

/// Linux `map_write`'s capability gate: the writer needs `cap` in the
/// TARGET namespace's PARENT (`ns_capable(ns->parent, cap)`), not merely
/// in the target itself. The initial user namespace has no parent, so
/// this is never satisfied for it. # C: O(depth)
fn has_cap_in_parent(opener: &FileCred, target: &NamespaceRef, cap: u32) -> bool {
    match target.parent() {
        Some(parent) => opener.has_cap(cap)
            && nscg::proc_ns::user_ns_is_ancestor(&opener.user_namespace().pin(), &parent),
        None => false,
    }
}

fn update_map(opener: &FileCred, owner: &NamespaceRef, kind: IdMapKind, src: &[u8])
    -> KResult<usize>
{
    let cap = match kind { IdMapKind::Uid => sched::cap::SETUID, IdMapKind::Gid => sched::cap::SETGID };
    let privileged = has_cap_in_parent(opener, owner, cap);
    let extents = parse_extents(src)?;
    let writer_own_id = match kind {
        IdMapKind::Uid => opener.dac().uid, IdMapKind::Gid => opener.dac().gid,
    };
    user_ns::write_map(owner, kind, privileged, writer_own_id, &extents).map_err(error)?;
    Ok(src.len())
}

/// Linux `proc_setgroups_write`'s capability gate: `CAP_SYS_ADMIN` held IN
/// the target namespace itself (or a descendant's opener reaching up to
/// it) — unlike uid_map/gid_map this is NOT the parent. # C: O(depth)
fn update_setgroups(opener: &FileCred, owner: &NamespaceRef, src: &[u8]) -> KResult<usize> {
    if !opener.has_cap(sched::cap::SYS_ADMIN)
        || !nscg::proc_ns::user_ns_is_ancestor(&opener.user_namespace().pin(), &owner.pin())
    {
        return Err(VfsError::Eperm);
    }
    let policy = parse_setgroups(src)?;
    user_ns::write_setgroups(owner, policy).map_err(error)?;
    Ok(src.len())
}

#[cfg(target_os = "oxide-kernel")]
struct UidGidMap { tid: u32, kind: IdMapKind }

#[cfg(target_os = "oxide-kernel")]
fn target(tid: u32) -> KResult<Arc<sched::Task>> {
    sched::live::registry::lookup(tid).ok_or(VfsError::Esrch)
}

#[cfg(target_os = "oxide-kernel")]
struct UidGidMapOps;

#[cfg(target_os = "oxide-kernel")]
impl FileOps for UidGidMapOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<UidGidMap>().ok_or(VfsError::Einval)?;
        let task = target(data.tid)?;
        Ok(crate::dyn_file::read_at(&body_map(&target_owner(&task)?, data.kind)?, off, buf))
    }

    fn write_file(&self, file: &File, off: u64, src: &[u8]) -> KResult<usize> {
        if off != 0 { return Err(VfsError::Einval); }
        let data = file.inode().private::<UidGidMap>().ok_or(VfsError::Einval)?;
        let task = target(data.tid)?;
        update_map(file.file_cred(), &target_owner(&task)?, data.kind, src)
    }

    fn write_nonblock_file(&self, file: &File, off: u64, src: &[u8]) -> KResult<usize> {
        self.write_file(file, off, src)
    }
}

#[cfg(target_os = "oxide-kernel")]
/// Build one target-task `uid_map`/`gid_map` file. # C: O(1)
pub fn make(tid: u32, kind: IdMapKind) -> InodeRef {
    let tag = match kind { IdMapKind::Uid => 0x2b, IdMapKind::Gid => 0x2c };
    InodeBuilder::new(super::live::pid_ino(tag, tid),
        mk_mode(FileType::Regular, FILE_MODE), default_inode_ops(), Arc::new(UidGidMapOps))
        .private(Arc::new(UidGidMap { tid, kind }))
        .build()
}

#[cfg(target_os = "oxide-kernel")]
struct SetgroupsFile { tid: u32 }

#[cfg(target_os = "oxide-kernel")]
struct SetgroupsOps;

#[cfg(target_os = "oxide-kernel")]
impl FileOps for SetgroupsOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<SetgroupsFile>().ok_or(VfsError::Einval)?;
        let task = target(data.tid)?;
        Ok(crate::dyn_file::read_at(&body_setgroups(&target_owner(&task)?)?, off, buf))
    }

    fn write_file(&self, file: &File, off: u64, src: &[u8]) -> KResult<usize> {
        if off != 0 { return Err(VfsError::Einval); }
        let data = file.inode().private::<SetgroupsFile>().ok_or(VfsError::Einval)?;
        let task = target(data.tid)?;
        update_setgroups(file.file_cred(), &target_owner(&task)?, src)
    }

    fn write_nonblock_file(&self, file: &File, off: u64, src: &[u8]) -> KResult<usize> {
        self.write_file(file, off, src)
    }
}

#[cfg(target_os = "oxide-kernel")]
/// Build one target-task `setgroups` file. # C: O(1)
pub fn make_setgroups(tid: u32) -> InodeRef {
    InodeBuilder::new(super::live::pid_ino(0x2d, tid),
        mk_mode(FileType::Regular, FILE_MODE), default_inode_ops(), Arc::new(SetgroupsOps))
        .private(Arc::new(SetgroupsFile { tid }))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use namespace_identity::{allocate, initial, NamespaceKind};

    fn child_of(parent: &NamespaceRef) -> NamespaceRef {
        allocate(NamespaceKind::User, parent.clone(), Some(parent.clone())).unwrap()
    }

    fn root_child() -> NamespaceRef { child_of(&initial(NamespaceKind::User)) }

    fn opener_root() -> FileCred { FileCred::root() }

    fn opener(user_namespace: NamespaceRef, cap_effective: u64, uid: u32, gid: u32) -> FileCred {
        let mut dac = vfs::Cred::root();
        dac.uid = uid;
        dac.gid = gid;
        FileCred::new(dac, user_namespace, cap_effective)
    }

    #[test]
    fn read_format_matches_linux_seq_show_and_empty_for_unset() {
        let owner = root_child();
        assert_eq!(body_map(&owner, IdMapKind::Uid).unwrap(), b"".to_vec());
        update_map(&opener_root(), &owner, IdMapKind::Uid, b"0 100000 65536\n").unwrap();
        assert_eq!(body_map(&owner, IdMapKind::Uid).unwrap(),
            b"         0     100000      65536\n".to_vec());
    }

    #[test]
    fn initial_namespace_reads_fixed_identity() {
        let init = initial(NamespaceKind::User);
        assert_eq!(body_map(&init, IdMapKind::Uid).unwrap(),
            format!("{:>10} {:>10} {:>10}\n", 0, 0, u32::MAX).into_bytes());
    }

    #[test]
    fn unprivileged_writer_may_only_map_its_own_id() {
        let owner = root_child();
        let non_root = opener(initial(NamespaceKind::User), 0, 1000, 1000);
        assert_eq!(update_map(&non_root, &owner, IdMapKind::Uid, b"0 2000 1\n"),
            Err(VfsError::Eperm));
        assert_eq!(update_map(&non_root, &owner, IdMapKind::Uid, b"0 1000 1\n"), Ok(9));
    }

    #[test]
    fn privileged_parent_capability_allows_arbitrary_map() {
        let owner = root_child();
        let parent_root = opener(initial(NamespaceKind::User),
            1u64 << sched::cap::SETUID, 0, 0);
        let src: &[u8] = b"0 100000 1000\n1000 900000 1\n";
        assert_eq!(update_map(&parent_root, &owner, IdMapKind::Uid, src), Ok(src.len()));
        assert_eq!(user_ns::snapshot_map(&owner, IdMapKind::Uid).unwrap(), alloc::vec![
            IdMapExtent { ns_id: 0, host_id: 100_000, count: 1000 },
            IdMapExtent { ns_id: 1000, host_id: 900_000, count: 1 },
        ]);
    }

    #[test]
    fn cap_held_only_inside_target_ns_is_not_enough_for_map_write() {
        let owner = root_child();
        // Opener's own user_ns IS the target (not its parent) — real Linux
        // requires the capability in the PARENT, so a same-namespace holder
        // (even with the cap bit set) cannot bulk-write without matching
        // the single-own-id fallback.
        let same_ns_holder = opener(owner.clone(), 1u64 << sched::cap::SETUID, 1000, 1000);
        assert_eq!(update_map(&same_ns_holder, &owner, IdMapKind::Uid, b"0 2000 1\n"),
            Err(VfsError::Eperm));
        assert_eq!(update_map(&same_ns_holder, &owner, IdMapKind::Uid, b"0 1000 1\n"), Ok(9));
    }

    #[test]
    fn write_once_rejects_second_write() {
        let owner = root_child();
        update_map(&opener_root(), &owner, IdMapKind::Uid, b"0 0 1\n").unwrap();
        assert_eq!(update_map(&opener_root(), &owner, IdMapKind::Uid, b"0 1 1\n"),
            Err(VfsError::Eperm));
    }

    #[test]
    fn malformed_writes_are_einval() {
        let owner = root_child();
        assert_eq!(update_map(&opener_root(), &owner, IdMapKind::Uid, b"not a map\n"),
            Err(VfsError::Einval));
        assert_eq!(update_map(&opener_root(), &owner, IdMapKind::Uid, b""), Err(VfsError::Einval));
    }

    #[test]
    fn setgroups_default_allow_then_deny_then_gid_map_locks_it() {
        let owner = root_child();
        assert_eq!(body_setgroups(&owner).unwrap(), b"allow\n".to_vec());
        let root = opener_root();
        assert_eq!(update_setgroups(&root, &owner, b"deny\n"), Ok(5));
        assert_eq!(body_setgroups(&owner).unwrap(), b"deny\n".to_vec());
        update_map(&root, &owner, IdMapKind::Gid, b"0 0 1\n").unwrap();
        assert_eq!(update_setgroups(&root, &owner, b"allow\n"), Err(VfsError::Eperm));
    }

    #[test]
    fn unprivileged_gid_map_write_requires_setgroups_deny_first() {
        let owner = root_child();
        let non_root = opener(initial(NamespaceKind::User), 0, 1000, 1000);
        assert_eq!(update_map(&non_root, &owner, IdMapKind::Gid, b"0 1000 1\n"),
            Err(VfsError::Eperm));
        update_setgroups(&opener_root(), &owner, b"deny\n").unwrap();
        assert_eq!(update_map(&non_root, &owner, IdMapKind::Gid, b"0 1000 1\n"), Ok(9));
    }

    #[test]
    fn setgroups_write_requires_cap_sys_admin_in_target_ns() {
        let owner = root_child();
        let no_cap = opener(owner.clone(), 0, 0, 0);
        assert_eq!(update_setgroups(&no_cap, &owner, b"deny\n"), Err(VfsError::Eperm));
        let capable = opener(owner.clone(), 1u64 << sched::cap::SYS_ADMIN, 0, 0);
        assert_eq!(update_setgroups(&capable, &owner, b"deny\n"), Ok(5));
    }
}
