// `/proc/<pid>/coredump_filter` — a view of the target process's per-mm
// core-dump filter word, and the only way to change it. The value itself lives
// on the address space, so a write here is what a later dump of that process
// reads; procfs keeps no copy of its own.

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, VfsError};
use vmm::coredump_filter::{CoredumpFilter, FilterParseError};

use crate::ino::pid_ino;
use crate::dyn_file::read_at;

const FILE_MODE: u16 = 0o644;
const COREDUMP_FILTER_TAG: u64 = 0x48;

struct CoredumpFilterFile { tid: u32 }

fn task(tid: u32) -> KResult<Arc<sched::Task>> {
    sched::live::registry::lookup(tid).ok_or(VfsError::Esrch)
}

fn parse_error(e: FilterParseError) -> VfsError {
    match e {
        FilterParseError::Invalid => VfsError::Einval,
        FilterParseError::Range => VfsError::Erange,
    }
}

/// Rendered filter of `target`, or nothing at all when it has no address space
/// — a process without one has no mappings to choose between.
/// # C: O(1)
pub fn body(target: &sched::Task) -> Vec<u8> {
    // SAFETY: the caller's task reference keeps the task alive, and the mm slot is only read here.
    let Some(mm) = (unsafe { target.mm_ref() }) else { return Vec::new() };
    mm.coredump_filter().text().to_vec()
}

/// Apply a write to `target`'s address space. The value is decoded before the
/// target is inspected, so a malformed write is rejected as such whether or not
/// the target still has an address space. Returns the bytes consumed.
/// # C: O(len)
pub fn apply(target: &sched::Task, src: &[u8]) -> KResult<usize> {
    let filter = CoredumpFilter::parse(src).map_err(parse_error)?;
    // SAFETY: the caller's task reference keeps the task alive, and the mm slot is only read here.
    let Some(mm) = (unsafe { target.mm_ref() }) else { return Err(VfsError::Esrch) };
    mm.set_coredump_filter(filter);
    Ok(src.len())
}

struct CoredumpFilterOps;

impl FileOps for CoredumpFilterOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }

    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<CoredumpFilterFile>().ok_or(VfsError::Einval)?;
        let target = task(data.tid)?;
        Ok(read_at(&body(&target), off, buf))
    }

    fn write(&self, inode: &Inode, off: u64, src: &[u8]) -> KResult<usize> {
        let data = inode.private::<CoredumpFilterFile>().ok_or(VfsError::Einval)?;
        // The file holds one value, not a stream: a write always replaces it.
        if off != 0 { return Ok(src.len()); }
        let target = task(data.tid)?;
        apply(&target, src)
    }
}

/// Build one target-process core-dump filter file. # C: O(1)
pub fn make(tid: u32) -> InodeRef {
    InodeBuilder::new(pid_ino(COREDUMP_FILTER_TAG, tid),
        mk_mode(FileType::Regular, FILE_MODE), default_inode_ops(), Arc::new(CoredumpFilterOps))
        .private(Arc::new(CoredumpFilterFile { tid }))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sched::{SchedClass, Task};

    const WEIGHT: u32 = 1024;

    fn user_task(tid: u32) -> (Task, Arc<vmm::AddressSpace>) {
        let mm = vmm::AddressSpace::new(0).expect("address space");
        let t = Task::new_user(tid, "dumper", SchedClass::Normal { weight: WEIGHT }, Arc::clone(&mm));
        (t, mm)
    }

    #[test]
    fn a_fresh_process_reads_the_default_filter() {
        let (t, _mm) = user_task(7001);
        assert_eq!(body(&t), b"00000033\n".to_vec());
    }

    #[test]
    fn a_write_sticks_and_is_read_back_in_the_rendered_form() {
        let (t, mm) = user_task(7002);
        assert_eq!(apply(&t, b"0x1ff\n"), Ok(6));
        assert_eq!(mm.coredump_filter(), CoredumpFilter::all());
        assert_eq!(body(&t), b"000001ff\n".to_vec());
        assert_eq!(apply(&t, b"0"), Ok(1));
        assert_eq!(mm.coredump_filter(), CoredumpFilter::empty());
        assert_eq!(body(&t), b"00000000\n".to_vec());
    }

    /// The value is per-mm, so threads of one process see one filter and a
    /// write through either thread's file is the same write.
    #[test]
    fn threads_of_one_process_share_the_value() {
        let mm = vmm::AddressSpace::new(0).expect("address space");
        let leader = Task::new_user(7003, "dumper", SchedClass::Normal { weight: WEIGHT }, Arc::clone(&mm));
        let sibling = Task::new_user(7004, "dumper", SchedClass::Normal { weight: WEIGHT }, Arc::clone(&mm));
        assert_eq!(apply(&leader, b"0x104"), Ok(5));
        assert_eq!(body(&sibling), b"00000104\n".to_vec());
    }

    #[test]
    fn a_forked_child_starts_from_its_parents_value_and_then_diverges() {
        let (parent, parent_mm) = user_task(7005);
        assert_eq!(apply(&parent, b"0x1c"), Ok(4));
        let child_mm = parent_mm.fork(0).expect("fork address space");
        let child = Task::new_user(7006, "dumper", SchedClass::Normal { weight: WEIGHT }, Arc::clone(&child_mm));
        assert_eq!(body(&child), b"0000001c\n".to_vec());
        assert_eq!(apply(&child, b"0x1"), Ok(3));
        assert_eq!(body(&child), b"00000001\n".to_vec());
        assert_eq!(body(&parent), b"0000001c\n".to_vec());
    }

    /// Replacing the process image is not a reason to forget the choice.
    #[test]
    fn the_value_survives_an_image_replacement() {
        let (t, mm) = user_task(7007);
        assert_eq!(apply(&t, b"0x1ff"), Ok(5));
        let after_exec = vmm::AddressSpace::new_for_exec(0, &mm).expect("exec address space");
        assert_eq!(after_exec.coredump_filter(), CoredumpFilter::all());
    }

    #[test]
    fn a_malformed_write_is_rejected_and_changes_nothing() {
        let (t, mm) = user_task(7008);
        assert_eq!(apply(&t, b"nonsense"), Err(VfsError::Einval));
        assert_eq!(apply(&t, b"0x100000000"), Err(VfsError::Erange));
        assert_eq!(mm.coredump_filter(), CoredumpFilter::DEFAULT);
    }

    #[test]
    fn a_process_without_an_address_space_has_no_filter_to_show_or_set() {
        let t = Task::new(7009, "kt", SchedClass::Normal { weight: WEIGHT });
        assert!(body(&t).is_empty());
        assert_eq!(apply(&t, b"0x1"), Err(VfsError::Esrch));
        // The rejection order puts the value first: a malformed write is
        // malformed whether or not the target still has an address space.
        assert_eq!(apply(&t, b"nonsense"), Err(VfsError::Einval));
    }
}
