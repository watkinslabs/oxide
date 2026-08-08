// 319 memfd_create — one syscall, one file (docs/53 §0). ABI shim only: the
// flag ladder and the derived seal/mode state live in `memfd_flags.rs`
// (non-gated, hosted-tested); this file parses, fetches and encodes.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::vec::Vec;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{File, OpenFlags};

use crate::memfd_flags::{
    MFD_NAME_MAX_LEN, MFD_NAME_PREFIX, name_scan_err, sanitize_flags_for_pidns, setup,
};

#[inline]
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `alloc_name`: `"memfd:"` then
/// `strncpy_from_user(uname, MFD_NAME_MAX_LEN + 1)`. A NULL/unreadable pointer
/// is `EFAULT`; a name longer than the budget is `EINVAL`, not `ENAMETOOLONG`.
fn read_memfd_name(name_ptr: u64) -> Result<String, i64> {
    if name_ptr == 0 { return Err(err(Errno::Efault)); }
    let raw = match uaccess::strndup_user(name_ptr, (MFD_NAME_MAX_LEN + 1) as u64) {
        Ok(b) => b,
        Err(e) => return Err(err(name_scan_err(e))),
    };
    let mut name = Vec::with_capacity(MFD_NAME_PREFIX.len() + raw.len());
    name.extend_from_slice(MFD_NAME_PREFIX);
    name.extend_from_slice(&raw);
    Ok(vfs::path_from_bytes(&name))
}

/// The errno a failed huge-page file build reports — the three the reference's
/// `hugetlb_file_setup` distinguishes.
/// # C: O(1)
fn huge_setup_errno(e: ::fs::hugetlbfs::HugetlbSetupError) -> Errno {
    use ::fs::hugetlbfs::HugetlbSetupError as E;
    match e { E::NoSuchSize => Errno::Enodev, E::NoMemory => Errno::Enomem, E::NoSpace => Errno::Enospc }
}

/// `sys_memfd_create(name, flags)` — slot 319, `SYSCALL_DEFINE2(memfd_create)`.
/// Order is `sanitize_flags` → `alloc_name` →
/// `memfd_alloc_file`, which is why an undefined flag bit beats a bad name
/// pointer and a bad name pointer beats the hugetlb backing store's error.
/// # C: O(N_fds) for the fd-table alloc
pub fn sys_memfd_create(args: &SyscallArgs) -> i64 {
    let name_ptr = args.a0;
    // Linux declares `unsigned int flags`; the upper half of the register
    // never reaches the handler.
    let flags = args.a1 as u32;
    let cur = match sched::live::current() {
        Some(c) => c, None => return err(Errno::Ebadf),
    };
    let pid_namespace = match cur.namespace_owner(namespace_identity::NamespaceKind::Pid) {
        Some(namespace) => namespace,
        None => return err(Errno::Ebadf),
    };
    let eff = match sanitize_flags_for_pidns(flags, &pid_namespace) {
        Ok(f) => f,
        Err(e) => return err(e),
    };
    let name = match read_memfd_name(name_ptr) {
        Ok(name) => name,
        Err(e) => return e,
    };
    let st = setup(eff);
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return err(Errno::Ebadf),
    };
    // Every memfd carries the seal word — a memfd created WITHOUT
    // MFD_ALLOW_SEALING is not "unsealable", it is born holding F_SEAL_SEAL,
    // so F_GET_SEALS reads 1 and F_ADD_SEALS is EPERM.
    //
    // `MFD_HUGETLB` chooses the OTHER backing `memfd_alloc_file` can build: a
    // file on the kernel-private hugetlbfs mount, sized by the huge-page
    // selector the flag word carries. It starts empty, exactly as the shmem
    // one does, and grows when something maps it.
    let inode = if st.hugetlb {
        match ::fs::hugetlbfs::hugetlb_file_setup(0, st.huge_shift, st.perm, 0, 0) {
            Ok(i) => i,
            Err(e) => return err(huge_setup_errno(e)),
        }
    } else {
        ::fs::tmpfs::tmpfs_sealable_file()
    };
    if let Some(seals) = inode.fcntl_seals() {
        seals.store(st.seals, core::sync::atomic::Ordering::Release);
    }
    let _ = inode.set_perm(st.perm);
    // `shmem_get_inode` → `inode_init_owner`: the memfd belongs to the
    // creator's fsuid/fsgid, which is what fstat(2) on the fd reports.
    let cred = crate::pathresolve::current_cred();
    let _ = inode.set_owner(cred.uid, cred.gid);
    let dentry = vfs::dcache::d_alloc_pseudo(&name, inode.clone(), &crate::anon_dname::MEMFD_OPS);
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    let fd = match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => fd, Err(e) => return -(e as i64),
    };
    if st.cloexec {
        let _ = fdt.set_cloexec(fd, true);
    }
    fd as i64
}
