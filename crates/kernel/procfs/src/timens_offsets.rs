// Linux `/proc/<pid>/timens_offsets` view over canonical TIME namespace state.

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use namespace_identity::NamespaceRef;
use nscg::time_ns::{TimeNsClock, TimeNsError, TimeNsUpdate, TimeOffset};
use vfs::{KResult, VfsError};

#[cfg(target_os = "oxide-kernel")]
use hal::TimerOps;
#[cfg(target_os = "oxide-kernel")]
use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeRef};

#[cfg(target_os = "oxide-kernel")]
const FILE_MODE: u16 = 0o644;
const MONOTONIC: &str = "monotonic";
const BOOTTIME: &str = "boottime";
const MAX_CLOCKS: usize = 2;

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

fn parse(src: &[u8], host_ns: u64) -> KResult<Vec<TimeNsUpdate>> {
    let text = core::str::from_utf8(src).map_err(|_| VfsError::Einval)?;
    let fields: Vec<&str> = text.split_ascii_whitespace().collect();
    if fields.is_empty() || fields.len() % 3 != 0 || fields.len() / 3 > MAX_CLOCKS {
        return Err(VfsError::Einval);
    }
    let mut updates = Vec::with_capacity(fields.len() / 3);
    for fields in fields.chunks_exact(3) {
        let clock = match fields[0] {
            MONOTONIC => TimeNsClock::Monotonic,
            BOOTTIME => TimeNsClock::Boottime,
            _ => return Err(VfsError::Einval),
        };
        if updates.iter().any(|update: &TimeNsUpdate| update.clock == clock) {
            return Err(VfsError::Einval);
        }
        let offset = TimeOffset::new(parse_i64(fields[1])?, parse_i32(fields[2])?)
            .map_err(error)?;
        updates.push(TimeNsUpdate { clock, offset, host_ns });
    }
    Ok(updates)
}

fn update(current: &sched::Task, owner: &NamespaceRef, src: &[u8], host_ns: u64)
    -> KResult<usize>
{
    if !nscg::proc_ns::has_cap_for(current, &owner.owner_user_namespace(), sched::cap::SYS_TIME) {
        return Err(VfsError::Eperm);
    }
    let updates = parse(src, host_ns)?;
    nscg::time_ns::set_offsets(owner, &updates).map_err(error)?;
    Ok(src.len())
}

fn target_owner(task: &sched::Task) -> KResult<NamespaceRef> {
    task.time_namespace_for_children().ok_or(VfsError::Enoent)
}

#[cfg(target_os = "oxide-kernel")]
fn target(tid: u32) -> KResult<NamespaceRef> {
    target_owner(&sched::live::registry::lookup(tid).ok_or(VfsError::Enoent)?)
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
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<TimensOffsets>().ok_or(VfsError::Einval)?;
        Ok(crate::dyn_file::read_at(&body(&target(data.tid)?)?, off, buf))
    }

    fn write(&self, inode: &Inode, off: u64, src: &[u8]) -> KResult<usize> {
        if off != 0 { return Err(VfsError::Einval); }
        let data = inode.private::<TimensOffsets>().ok_or(VfsError::Einval)?;
        let current = sched::live::current().ok_or(VfsError::Esrch)?;
        update(&current, &target(data.tid)?, src, host_ns())
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

    #[test]
    fn linux_read_format_uses_both_canonical_offsets() {
        let owner = owner(initial(NamespaceKind::User));
        let current = sched::Task::new(910, "timens-reader", sched::SchedClass::Normal { weight: 1024 });
        update(&current, &owner, b"monotonic -2 500000000\nboottime 3 7\n",
            10_000_000_000).unwrap();
        assert_eq!(body(&owner).unwrap(),
            b"monotonic          -2 500000000\nboottime            3         7\n");
    }

    #[test]
    fn write_targets_time_for_children_owner_atomically() {
        let user = initial(NamespaceKind::User);
        let current_owner = owner(Arc::clone(&user));
        let children_owner = owner(user);
        let target = sched::Task::new(911, "timens-target", sched::SchedClass::Normal { weight: 1024 });
        assert!(target.replace_time_namespace_pair(
            Arc::clone(&current_owner), Arc::clone(&children_owner)).is_ok());
        let writer = sched::Task::new(912, "timens-writer", sched::SchedClass::Normal { weight: 1024 });
        let selected = target_owner(&target).unwrap();

        let before = nscg::time_ns::snapshot(&selected).unwrap();
        assert_eq!(update(&writer, &selected,
            b"monotonic 1 0\nboottime -20 0\n", 10_000_000_000), Err(VfsError::Erange));
        assert_eq!(nscg::time_ns::snapshot(&selected).unwrap(), before);
        assert_eq!(nscg::time_ns::snapshot(&current_owner).unwrap().offsets,
            nscg::time_ns::TimeNsOffsets::ZERO);
    }

    #[test]
    fn write_enforces_owner_capability_frozen_clock_and_range_errors() {
        let user = allocate(NamespaceKind::User, initial(NamespaceKind::User),
            Some(initial(NamespaceKind::User))).unwrap();
        let owner = owner(Arc::clone(&user));
        let writer = sched::Task::new(913, "timens-errors", sched::SchedClass::Normal { weight: 1024 });
        let sibling_user = allocate(NamespaceKind::User, initial(NamespaceKind::User),
            Some(initial(NamespaceKind::User))).unwrap();
        assert!(writer.replace_namespace(sibling_user).is_ok());
        assert_eq!(update(&writer, &owner, b"monotonic 1 0\n", 10_000_000_000),
            Err(VfsError::Eperm));
        assert!(writer.replace_namespace(initial(NamespaceKind::User)).is_ok());
        writer.creds.cap_effective.store(0, Ordering::Release);
        assert_eq!(update(&writer, &owner, b"monotonic 1 0\n", 10_000_000_000),
            Err(VfsError::Eperm));

        writer.creds.cap_effective.store(1u64 << sched::cap::SYS_TIME, Ordering::Release);
        assert_eq!(update(&writer, &owner, b"realtime 1 0\n", 10_000_000_000),
            Err(VfsError::Einval));
        assert_eq!(update(&writer, &owner, b"monotonic 9223372036854775808 0\n",
            10_000_000_000), Err(VfsError::Erange));
        nscg::time_ns::freeze(&owner).unwrap();
        assert_eq!(update(&writer, &owner, b"monotonic 1 0\n", 10_000_000_000),
            Err(VfsError::Eacces));
    }
}
