// Linux `/proc/<pid>/timens_offsets` view over canonical TIME namespace state.

use alloc::format;
#[cfg(target_os = "oxide-kernel")]
use alloc::sync::Arc;
use alloc::vec::Vec;

use namespace_identity::NamespaceRef;
use nscg::time_ns::{TimeNsClock, TimeNsError, TimeNsUpdate, TimeOffset};
use vfs::{FileCred, KResult, VfsError};

#[cfg(target_os = "oxide-kernel")]
use hal::TimerOps;
#[cfg(target_os = "oxide-kernel")]
use vfs::{default_inode_ops, mk_mode, File, FileOps, FileType, Inode, InodeBuilder, InodeRef};

#[cfg(target_os = "oxide-kernel")]
const FILE_MODE: u16 = 0o644;
const MONOTONIC: &str = "monotonic";
const BOOTTIME: &str = "boottime";
const MAX_CLOCKS: usize = 2;
const PAGE_SIZE: usize = 4096;

#[cfg(target_os = "oxide-kernel")]
struct TimensOffsets { tid: u32 }

fn error(err: TimeNsError) -> VfsError {
    match err {
        TimeNsError::Frozen => VfsError::Eacces,
        TimeNsError::InvalidClockTime | TimeNsError::OffsetOutOfRange => VfsError::Erange,
        TimeNsError::WrongKind | TimeNsError::InitialClone | TimeNsError::StateExists
        | TimeNsError::StateMissing | TimeNsError::InvalidOffset => VfsError::Einval,
    }
}

fn body(owner: &NamespaceRef) -> KResult<Vec<u8>> {
    let offsets = nscg::time_ns::snapshot(owner).map_err(error)?.offsets;
    Ok(format!("{:<10} {:>10} {:>9}\n{:<10} {:>10} {:>9}\n",
        MONOTONIC, offsets.monotonic.seconds, offsets.monotonic.nanoseconds,
        BOOTTIME, offsets.boottime.seconds, offsets.boottime.nanoseconds).into_bytes())
}

fn parse_i64(value: &str) -> KResult<i64> {
    value.parse::<i64>().map_err(|err| match err.kind() {
        core::num::IntErrorKind::PosOverflow | core::num::IntErrorKind::NegOverflow => VfsError::Erange,
        _ => VfsError::Einval,
    })
}

fn parse_i32(value: &str) -> KResult<i32> {
    value.parse::<i32>().map_err(|err| match err.kind() {
        core::num::IntErrorKind::PosOverflow | core::num::IntErrorKind::NegOverflow => VfsError::Erange,
        _ => VfsError::Einval,
    })
}

fn parse(src: &[u8], host_ns: u64) -> KResult<(Vec<TimeNsUpdate>, usize)> {
    if src.is_empty() || src.len() >= PAGE_SIZE { return Err(VfsError::Einval); }
    let text = core::str::from_utf8(src).map_err(|_| VfsError::Einval)?;
    let mut updates = Vec::with_capacity(MAX_CLOCKS);
    let mut consumed = 0usize;
    for line in text.split_inclusive('\n').take(MAX_CLOCKS) {
        let fields: Vec<&str> = line.trim_end_matches('\n').split_ascii_whitespace().collect();
        if fields.len() != 3 { return Err(VfsError::Einval); }
        let clock = match fields[0] {
            MONOTONIC | "1" => TimeNsClock::Monotonic,
            BOOTTIME | "7" => TimeNsClock::Boottime,
            _ => return Err(VfsError::Einval),
        };
        let offset = TimeOffset::new(parse_i64(fields[1])?, parse_i32(fields[2])?)
            .map_err(error)?;
        updates.push(TimeNsUpdate { clock, offset, host_ns });
        consumed += line.len();
    }
    if updates.is_empty() { return Err(VfsError::Einval); }
    Ok((updates, consumed))
}

fn update(opener: &FileCred, owner: &NamespaceRef, src: &[u8], host_ns: u64)
    -> KResult<usize>
{
    let target_user = owner.owner_user_namespace();
    let opener_user = opener.user_namespace().pin();
    if !opener.has_cap(sched::cap::SYS_TIME)
        || !nscg::proc_ns::user_ns_is_ancestor(&opener_user, &target_user)
    {
        return Err(VfsError::Eperm);
    }
    let (updates, consumed) = parse(src, host_ns)?;
    nscg::time_ns::set_offsets(owner, &updates).map_err(error)?;
    Ok(consumed)
}

fn update_target(opener: &FileCred, target: &sched::Task, src: &[u8], host_ns: u64)
    -> KResult<usize>
{
    update(opener, &target_owner(target)?, src, host_ns)
}

fn target_owner(task: &sched::Task) -> KResult<NamespaceRef> {
    task.time_namespace_for_children().ok_or(VfsError::Esrch)
}

#[cfg(target_os = "oxide-kernel")]
fn target(tid: u32) -> KResult<Arc<sched::Task>> {
    sched::live::registry::lookup(tid).ok_or(VfsError::Esrch)
}

#[cfg(target_os = "oxide-kernel")]
fn host_ns() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

#[cfg(target_os = "oxide-kernel")]
struct TimensOffsetsOps;

#[cfg(target_os = "oxide-kernel")]
impl FileOps for TimensOffsetsOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<TimensOffsets>().ok_or(VfsError::Einval)?;
        let target = target(data.tid)?;
        Ok(crate::dyn_file::read_at(&body(&target_owner(&target)?)?, off, buf))
    }

    fn write_file(&self, file: &File, off: u64, src: &[u8]) -> KResult<usize> {
        if off != 0 { return Err(VfsError::Einval); }
        let data = file.inode().private::<TimensOffsets>().ok_or(VfsError::Einval)?;
        let target = target(data.tid)?;
        update_target(file.file_cred(), &target, src, host_ns())
    }

    fn write_nonblock_file(&self, file: &File, off: u64, src: &[u8]) -> KResult<usize> {
        self.write_file(file, off, src)
    }
}

#[cfg(target_os = "oxide-kernel")]
/// Build one target-task time namespace offsets file. # C: O(1)
pub fn make(tid: u32) -> InodeRef {
    InodeBuilder::new(super::live::pid_ino(0x2a, tid),
        mk_mode(FileType::Regular, FILE_MODE), default_inode_ops(), Arc::new(TimensOffsetsOps))
        .private(Arc::new(TimensOffsets { tid }))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;
    use namespace_identity::{allocate, initial, NamespaceKind};

    fn owner(user: NamespaceRef) -> NamespaceRef {
        let owner = allocate(NamespaceKind::Time, user, None).unwrap();
        nscg::time_ns::clone_from(&owner, &initial(NamespaceKind::Time)).unwrap();
        owner
    }

    fn opener(task: &sched::Task) -> FileCred {
        let effective = task.creds.cap_effective.load(Ordering::Acquire);
        FileCred::new(vfs::Cred::root(), task.namespace_owner(NamespaceKind::User).unwrap(), effective)
    }

    #[test]
    fn linux_read_format_uses_both_canonical_offsets() {
        let owner = owner(initial(NamespaceKind::User));
        update(&FileCred::root(), &owner, b"monotonic -2 500000000\nboottime 3 7\n",
            10_000_000_000).unwrap();
        assert_eq!(body(&owner).unwrap(),
            b"monotonic          -2 500000000\nboottime            3         7\n");
    }

    #[test]
    fn write_targets_time_for_children_owner_atomically() {
        let user = initial(NamespaceKind::User);
        let current_owner = owner(user.clone());
        let children_owner = owner(user);
        let target = sched::Task::new(911, "timens-target", sched::SchedClass::Normal { weight: 1024 });
        assert!(target.replace_time_namespace_pair(
            current_owner.clone(), children_owner.clone()).is_ok());
        let writer = FileCred::root();
        let selected = target_owner(&target).unwrap();

        let before = nscg::time_ns::snapshot(&selected).unwrap();
        assert_eq!(update_target(&writer, &target,
            b"monotonic 1 0\nboottime -20 0\n", 10_000_000_000), Err(VfsError::Erange));
        assert_eq!(nscg::time_ns::snapshot(&selected).unwrap(), before);
        assert_eq!(nscg::time_ns::snapshot(&current_owner).unwrap().offsets,
            nscg::time_ns::TimeNsOffsets::ZERO);
    }

    #[test]
    fn write_enforces_owner_capability_frozen_clock_and_range_errors() {
        let user = allocate(NamespaceKind::User, initial(NamespaceKind::User),
            Some(initial(NamespaceKind::User))).unwrap();
        let owner = owner(user.clone());
        let sibling_user = allocate(NamespaceKind::User, initial(NamespaceKind::User),
            Some(initial(NamespaceKind::User))).unwrap();
        let sibling = FileCred::new(vfs::Cred::root(), sibling_user,
            1u64 << sched::cap::SYS_TIME);
        assert_eq!(update(&sibling, &owner, b"monotonic 1 0\n", 10_000_000_000),
            Err(VfsError::Eperm));
        let no_cap = FileCred::new(vfs::Cred::root(), initial(NamespaceKind::User), 0);
        assert_eq!(update(&no_cap, &owner, b"monotonic 1 0\n", 10_000_000_000),
            Err(VfsError::Eperm));

        let writer = FileCred::root();
        assert_eq!(update(&writer, &owner, b"realtime 1 0\n", 10_000_000_000),
            Err(VfsError::Einval));
        assert_eq!(update(&writer, &owner, b"monotonic 9223372036854775808 0\n",
            10_000_000_000), Err(VfsError::Erange));
        nscg::time_ns::freeze(&owner).unwrap();
        assert_eq!(update(&writer, &owner, b"monotonic 1 0\n", 10_000_000_000),
            Err(VfsError::Eacces));
    }

    #[test]
    fn privileged_opener_stays_allowed_after_current_drops_cap_and_moves() {
        let target_user = allocate(NamespaceKind::User, initial(NamespaceKind::User),
            Some(initial(NamespaceKind::User))).unwrap();
        let target_owner = owner(target_user);
        let target = sched::Task::new(914, "timens-target", sched::SchedClass::Normal { weight: 1024 });
        assert!(target.replace_time_namespace_for_children(target_owner).is_ok());
        let current = sched::Task::new(915, "timens-opener", sched::SchedClass::Normal { weight: 1024 });
        let file_cred = opener(&current);

        current.creds.cap_effective.store(0, Ordering::Release);
        let moved = allocate(NamespaceKind::User, initial(NamespaceKind::User),
            Some(initial(NamespaceKind::User))).unwrap();
        assert!(current.replace_namespace(moved).is_ok());

        assert_eq!(update_target(&file_cred, &target, b"monotonic 1 0\n", 10_000_000_000),
            Ok(b"monotonic 1 0\n".len()));
    }

    #[test]
    fn unprivileged_opener_stays_denied_after_current_gains_cap_and_moves() {
        let target_user = allocate(NamespaceKind::User, initial(NamespaceKind::User),
            Some(initial(NamespaceKind::User))).unwrap();
        let target_owner = owner(target_user);
        let target = sched::Task::new(916, "timens-target", sched::SchedClass::Normal { weight: 1024 });
        assert!(target.replace_time_namespace_for_children(target_owner).is_ok());
        let current = sched::Task::new(917, "timens-opener", sched::SchedClass::Normal { weight: 1024 });
        let sibling = allocate(NamespaceKind::User, initial(NamespaceKind::User),
            Some(initial(NamespaceKind::User))).unwrap();
        assert!(current.replace_namespace(sibling).is_ok());
        current.creds.cap_effective.store(0, Ordering::Release);
        let file_cred = opener(&current);

        assert!(current.replace_namespace(initial(NamespaceKind::User)).is_ok());
        current.creds.cap_effective.store(1u64 << sched::cap::SYS_TIME, Ordering::Release);

        assert_eq!(update_target(&file_cred, &target, b"monotonic 1 0\n", 10_000_000_000),
            Err(VfsError::Eperm));
    }

    #[test]
    fn parser_matches_linux_two_line_prefix_and_numeric_clock_names() {
        let (updates, consumed) = parse(
            b"1 1 0\n1 2 0\ninvalid ignored tail\n", 10_000_000_000).unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].clock, TimeNsClock::Monotonic);
        assert_eq!(updates[1].clock, TimeNsClock::Monotonic);
        assert_eq!(consumed, b"1 1 0\n1 2 0\n".len());

        let (updates, consumed) = parse(b"7 -1 500000000", 10_000_000_000).unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].clock, TimeNsClock::Boottime);
        assert_eq!(consumed, b"7 -1 500000000".len());
        assert_eq!(parse(&[b'x'; PAGE_SIZE], 0), Err(VfsError::Einval));
    }
}
