#[repr(C)]
struct NativeMsghdr {
    name: u64,
    namelen: u32,
    _name_pad: u32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
    flags: u32,
    _flags_pad: u32,
}

#[repr(C)]
struct NativeMmsghdr {
    msg: NativeMsghdr,
    len: u32,
    _pad: u32,
}

#[repr(C)]
struct NativeTimespec {
    sec: i64,
    nsec: i64,
}

pub(crate) const MMSGHDR_SIZE: u64 = core::mem::size_of::<NativeMmsghdr>() as u64;
pub(crate) const MMSGHDR_LEN_OFFSET: u64 = core::mem::offset_of!(NativeMmsghdr, len) as u64;
pub(crate) const MMSGHDR_FLAGS_OFFSET: u64 =
    core::mem::offset_of!(NativeMmsghdr, msg) as u64
        + core::mem::offset_of!(NativeMsghdr, flags) as u64;
pub(crate) const TIMESPEC_SIZE: usize = core::mem::size_of::<NativeTimespec>();

const _: [(); 64] = [(); core::mem::size_of::<NativeMmsghdr>()];
const _: [(); 56] = [(); core::mem::offset_of!(NativeMmsghdr, len)];
const _: [(); 48] = [(); core::mem::offset_of!(NativeMsghdr, flags)];
const _: [(); 16] = [(); core::mem::size_of::<NativeTimespec>()];
