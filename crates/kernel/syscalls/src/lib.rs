// Glue between per-arch syscall asm stub and dispatch table per `15§4`.

#![no_std]

#[cfg(target_os = "oxide-kernel")]
include!("kernel_body.rs");

#[cfg(all(test, not(target_os = "oxide-kernel")))]
extern crate alloc;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
extern crate std;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod fd_pair;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod recv_user;


#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod namei_common {
    use alloc::string::String;

    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(_addr: u64) -> Result<String, i64> {
        Err(-(syscall::errno::Errno::Efault.as_i32() as i64))
    }
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod pathresolve {
    pub fn resolve_path_raw(_raw: &str, _follow: bool) -> vfs::KResult<vfs::VfsPath> {
        Err(vfs::VfsError::Enoent)
    }
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "179_quotactl.rs"] pub mod s179_quotactl;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "443_quotactl_fd.rs"] pub mod s443_quotactl_fd;
