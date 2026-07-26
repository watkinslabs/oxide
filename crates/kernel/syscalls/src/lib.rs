// Glue between per-arch syscall asm stub and dispatch table per `15§4`.

#![no_std]

extern crate alloc;

mod net_errno;
mod fcntl_dup;
mod exec_time;
mod perm_common;

#[cfg(target_os = "oxide-kernel")]
include!("kernel_body.rs");

#[cfg(any(target_os = "oxide-kernel", test))]
mod tcp_info;

#[cfg(any(target_os = "oxide-kernel", test))]
pub mod ptrace_perm;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
extern crate std;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod fd_pair;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod socket_fd;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod net_common;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod name_copyout;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "time_common.rs"]
mod time_common;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod io_uring_sqe;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod packet_mmap;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod recv_user;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod recv_control;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "recvmsg/entry.rs"]
mod recvmsg_entry_hosted;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod send_user;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod socket_control_tests;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod getdents_debug_tests;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod poll_ownership_tests;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod fcntl_dup_tests;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "recvmsg/vsock.rs"]
mod vsock_recv_shutdown_boundary;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "016_ioctl/netns_fd.rs"]
mod siocgskns_fd;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "054_setsockopt/multicast.rs"]
mod mcast_set_boundary;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "054_setsockopt/packet_abi.rs"]
mod packet_membership_abi;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "055_getsockopt/packet_abi.rs"]
mod packet_get_abi;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "055_getsockopt/multicast.rs"]
mod mcast_get_boundary;

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

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "470_listns.rs"] pub mod s470_listns;
