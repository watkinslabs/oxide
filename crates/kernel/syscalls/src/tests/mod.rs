//! Hosted syscall tests that do not belong to one production subsystem.
//!
//! The explicit paths keep these test modules at their existing source
//! locations while giving the test harness a single module-local home.

#[cfg(not(target_os = "oxide-kernel"))]
#[path = "../socket_control_tests.rs"]
mod socket_control_tests;
#[cfg(not(target_os = "oxide-kernel"))]
#[path = "../getdents_debug_tests.rs"]
mod getdents_debug_tests;
#[cfg(not(target_os = "oxide-kernel"))]
#[path = "../poll_ownership_tests.rs"]
mod poll_ownership_tests;
#[cfg(not(target_os = "oxide-kernel"))]
#[path = "../fcntl_dup_tests.rs"]
mod fcntl_dup_tests;

#[path = "../return_fastpath_tests.rs"]
mod return_fastpath_tests;
#[path = "../tty_ioctl_source_tests.rs"]
mod tty_ioctl_source_tests;

#[cfg(not(target_os = "oxide-kernel"))]
#[path = "../recvmsg/vsock.rs"]
mod vsock_recv_shutdown_boundary;
#[cfg(not(target_os = "oxide-kernel"))]
#[path = "../016_ioctl/netns_fd.rs"]
mod siocgskns_fd;
#[cfg(not(target_os = "oxide-kernel"))]
#[path = "../054_setsockopt/multicast.rs"]
mod mcast_set_boundary;
#[cfg(not(target_os = "oxide-kernel"))]
#[path = "../054_setsockopt/packet_abi.rs"]
mod packet_membership_abi;
#[cfg(not(target_os = "oxide-kernel"))]
#[path = "../055_getsockopt/packet_abi.rs"]
mod packet_get_abi;
#[cfg(not(target_os = "oxide-kernel"))]
#[path = "../055_getsockopt/out.rs"]
mod out;
#[cfg(not(target_os = "oxide-kernel"))]
#[path = "../055_getsockopt/multicast.rs"]
mod mcast_get_boundary;
