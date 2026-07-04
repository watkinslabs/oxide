use core::ffi::c_void;

pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_RAW: i32 = 3;
pub const SOCK_CLOEXEC: i32 = 0o2000000;
pub const SOCK_NONBLOCK: i32 = 0o4000;
pub const SOL_SOCKET: i32 = 1;
pub const SO_REUSEADDR: i32 = 2;
pub const SO_ERROR: i32 = 4;
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

#[repr(C)]
pub struct sockaddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16, // network byte order
    pub sin_addr: u32, // network byte order
    pub sin_zero: [u8; 8],
}
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}
#[repr(C)]
pub struct sockaddr_storage {
    pub ss_family: u16,
    __ss_padding: [u8; 118],
    __ss_align: u64,
}
#[repr(C)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}
#[repr(C)]
pub struct msghdr {
    pub msg_name: *mut c_void,
    pub msg_namelen: u32,
    __pad1: u32,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: usize,
    pub msg_control: *mut c_void,
    pub msg_controllen: usize,
    pub msg_flags: i32,
    __pad2: u32,
}

const _: () = assert!(core::mem::size_of::<sockaddr>() == 16);
const _: () = assert!(core::mem::size_of::<sockaddr_in>() == 16);
const _: () = assert!(core::mem::size_of::<sockaddr_in6>() == 28);
const _: () = assert!(core::mem::size_of::<sockaddr_storage>() == 128);
const _: () = assert!(core::mem::size_of::<msghdr>() == 56);
const _: () = assert!(core::mem::size_of::<iovec>() == 16);
