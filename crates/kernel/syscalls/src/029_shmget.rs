// 029 shmget — SysV shm creation shim (docs/53 §0). The ipc crate can't reach
// the filesystems a segment is built on, so this ABI-layer shim turns the
// registry's decision into the object it names and hands it back. Every shmat
// maps THAT one object MAP_SHARED, so all attaches (and their forked children)
// share the same physical frames — real Linux SysV shm.
//
// Two kinds of object, chosen by the registry, never by this file: an
// anonymous tmpfs inode for an ordinary segment, and a file on the
// kernel-private hugetlbfs mount for a `SHM_HUGETLB` one. Which granule and
// how many bytes is the registry's answer (`ipc::sysv_shm::SegBacking`); the
// permission to ask for huge pages at all is checked there too.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use syscall::SyscallArgs;
use syscall::errno::Errno;

/// The errno a failed huge-page file build reports — the three the huge-page
/// file setup distinguishes.
/// # C: O(1)
fn huge_setup_errno(e: ::fs::hugetlbfs::HugetlbSetupError) -> Errno {
    use ::fs::hugetlbfs::HugetlbSetupError as E;
    match e { E::NoSuchSize => Errno::Enodev, E::NoMemory => Errno::Enomem, E::NoSpace => Errno::Enospc }
}

/// Permissions the segment's backing file carries. The segment's own access
/// control is the IPC permission block, which is checked before any attach
/// reaches the file, so the file itself is open to its holder.
const SHM_FILE_PERM: u16 = 0o777;

/// Build the object a new segment is backed by. # C: O(pages) for a huge file
fn make_backing(want: ipc::sysv_shm::SegBacking)
    -> Result<Arc<dyn vmm::FileBacking>, Errno>
{
    let inode = match want {
        ipc::sysv_shm::SegBacking::Shmem => ::fs::tmpfs::tmpfs_anon_file(),
        // The pages are promised HERE, so a segment larger than the pool can
        // hold fails at `shmget` rather than at a fault the program that
        // attached it cannot handle.
        ipc::sysv_shm::SegBacking::Huge { log, bytes } => {
            match ::fs::hugetlbfs::hugetlb_file_setup(bytes, log, SHM_FILE_PERM, 0, 0) {
                Ok(i) => i,
                Err(e) => return Err(huge_setup_errno(e)),
            }
        }
    };
    Ok(crate::mmap_file::InodeFileBacking::new(inode))
}

/// `sys_shmget(key, size, shmflg)` — slot 29.
/// # C: O(N_segments) on lookup
pub fn sys_shmget(args: &SyscallArgs) -> i64 {
    let key  = args.a0 as i32;
    let size = args.a1 as usize;
    // Linux declares `int shmflg`; the upper half of the register never
    // reaches the handler, and the size selector lives inside that half.
    let flg  = (args.a2 as u32) as u64;
    let cpid = sched::live::current()
        .map(|c| c.vtgid.load(core::sync::atomic::Ordering::Acquire))
        .unwrap_or(0);
    ipc::sysv_shm::shmget_with_backing(key, size, flg, cpid, make_backing)
}
