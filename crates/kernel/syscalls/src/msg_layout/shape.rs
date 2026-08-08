// The two message-ABI shapes, as data. Nothing here decides anything: the
// choice between them belongs to `super::entry`.

/// Native LP64 `msghdr`, laid out so the offsets below are computed rather
/// than asserted.
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

/// 32-bit `msghdr`: every pointer and every size is 4 bytes wide, and the
/// structure carries no padding at all.
#[repr(C)]
struct CompatMsghdr {
    name: u32,
    namelen: u32,
    iov: u32,
    iovlen: u32,
    control: u32,
    controllen: u32,
    flags: u32,
}

#[repr(C)]
struct CompatMmsghdr {
    msg: CompatMsghdr,
    len: u32,
}

#[repr(C)]
struct NativeTimespec {
    sec: i64,
    nsec: i64,
}

/// `sizeof(struct __kernel_timespec)` — the batch timeout is a 64-bit
/// timespec on both ABIs the kernel serves.
pub const TIMESPEC_SIZE: usize = core::mem::size_of::<NativeTimespec>();

const NATIVE_MSGHDR: usize = core::mem::size_of::<NativeMsghdr>();
const COMPAT_MSGHDR: usize = core::mem::size_of::<CompatMsghdr>();
const NATIVE_CMSGHDR: usize = 16;
const COMPAT_CMSGHDR: usize = 12;

// The ABI numbers this file exists to pin. A shape that drifts is a silently
// mis-parsed message, not a compile error, so state them.
const _: [(); 56] = [(); NATIVE_MSGHDR];
const _: [(); 28] = [(); COMPAT_MSGHDR];
const _: [(); 64] = [(); core::mem::size_of::<NativeMmsghdr>()];
const _: [(); 32] = [(); core::mem::size_of::<CompatMmsghdr>()];
const _: [(); 56] = [(); core::mem::offset_of!(NativeMmsghdr, len)];
const _: [(); 28] = [(); core::mem::offset_of!(CompatMmsghdr, len)];
const _: [(); 16] = [(); TIMESPEC_SIZE];

/// Which `msghdr`/`cmsghdr`/`mmsghdr` shape one message syscall speaks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MsgLayout {
    /// The kernel's own LP64 shape.
    #[default]
    Native,
    /// The 32-bit shape a compat caller passes.
    Compat,
}

/// Byte offsets of one `msghdr`'s fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MsghdrOffsets {
    pub name: usize,
    pub namelen: usize,
    pub iov: usize,
    pub iovlen: usize,
    pub control: usize,
    pub controllen: usize,
    pub flags: usize,
}

const NATIVE_OFFSETS: MsghdrOffsets = MsghdrOffsets {
    name: core::mem::offset_of!(NativeMsghdr, name),
    namelen: core::mem::offset_of!(NativeMsghdr, namelen),
    iov: core::mem::offset_of!(NativeMsghdr, iov),
    iovlen: core::mem::offset_of!(NativeMsghdr, iovlen),
    control: core::mem::offset_of!(NativeMsghdr, control),
    controllen: core::mem::offset_of!(NativeMsghdr, controllen),
    flags: core::mem::offset_of!(NativeMsghdr, flags),
};

const COMPAT_OFFSETS: MsghdrOffsets = MsghdrOffsets {
    name: core::mem::offset_of!(CompatMsghdr, name),
    namelen: core::mem::offset_of!(CompatMsghdr, namelen),
    iov: core::mem::offset_of!(CompatMsghdr, iov),
    iovlen: core::mem::offset_of!(CompatMsghdr, iovlen),
    control: core::mem::offset_of!(CompatMsghdr, control),
    controllen: core::mem::offset_of!(CompatMsghdr, controllen),
    flags: core::mem::offset_of!(CompatMsghdr, flags),
};

impl MsgLayout {
    /// True for the 32-bit shape. # C: O(1)
    pub const fn is_compat(self) -> bool { matches!(self, Self::Compat) }

    /// Width of one pointer or one `size_t` in this ABI. # C: O(1)
    pub const fn word(self) -> usize { if self.is_compat() { 4 } else { 8 } }

    /// `sizeof(struct msghdr)`. # C: O(1)
    pub const fn msghdr_size(self) -> usize {
        if self.is_compat() { COMPAT_MSGHDR } else { NATIVE_MSGHDR }
    }

    /// Field offsets within one `msghdr`. # C: O(1)
    pub const fn msghdr(self) -> MsghdrOffsets {
        if self.is_compat() { COMPAT_OFFSETS } else { NATIVE_OFFSETS }
    }

    /// `sizeof(struct iovec)`; base and length are one `word` each. # C: O(1)
    pub const fn iovec_size(self) -> usize { self.word() * 2 }

    /// Stride between `mmsghdr` entries. The 32-bit entry is 32 bytes, not 64.
    /// # C: O(1)
    pub const fn mmsghdr_size(self) -> u64 {
        // `msg_len` is one `unsigned int` after the header, and the whole
        // entry is padded to the ABI's own alignment: 64 native, 32 compat.
        let unpadded = self.msghdr_size() + core::mem::size_of::<u32>();
        let align = self.word();
        (unpadded.wrapping_add(align - 1) & !(align - 1)) as u64
    }

    /// Offset of `msg_len` within one `mmsghdr` — the field a completed
    /// send/receive publishes. # C: O(1)
    pub const fn mmsghdr_len_offset(self) -> u64 { self.msghdr_size() as u64 }

    /// Offset of `msg_hdr.msg_flags` within one `mmsghdr`, which is where a
    /// batch reads back the out-of-band verdict of the message it just
    /// delivered. # C: O(1)
    pub const fn mmsghdr_flags_offset(self) -> u64 { self.msghdr().flags as u64 }

    /// `sizeof(struct cmsghdr)`: `{ len, level, type }` with a 64-bit length
    /// natively and a 32-bit one in compat. # C: O(1)
    pub const fn cmsghdr_size(self) -> usize {
        if self.is_compat() { COMPAT_CMSGHDR } else { NATIVE_CMSGHDR }
    }

    /// `CMSG_ALIGN`'s granularity: `sizeof(size_t)` natively, `sizeof(s32)`
    /// in compat. This is the reason a compat control stream cannot simply be
    /// handed to a native parser. # C: O(1)
    pub const fn cmsg_align(self) -> usize { self.word() }

    /// `CMSG_ALIGN(n)` for this ABI. # C: O(1)
    pub const fn cmsg_aligned(self, n: usize) -> usize {
        let align = self.cmsg_align();
        n.wrapping_add(align - 1) & !(align - 1)
    }

    /// `CMSG_SPACE(len)` for this ABI. # C: O(1)
    pub const fn cmsg_space(self, data_len: usize) -> usize {
        self.cmsg_aligned(self.cmsghdr_size() + data_len)
    }

    /// Read one pointer or `size_t` field at `at`, zero-extending the 32-bit
    /// form the way `compat_ptr` does. # C: O(1)
    pub fn word_at(self, bytes: &[u8], at: usize) -> u64 {
        if self.is_compat() {
            u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap()) as u64
        } else {
            u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap())
        }
    }

    /// Read one 32-bit field (`msg_namelen`, `msg_flags`) at `at`. # C: O(1)
    pub fn u32_at(self, bytes: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    /// Encode one pointer or `size_t` value in this ABI's width. # C: O(1)
    pub fn word_bytes(self, value: u64) -> [u8; 8] {
        let mut out = [0u8; 8];
        if self.is_compat() { out[..4].copy_from_slice(&(value as u32).to_ne_bytes()); }
        else { out.copy_from_slice(&value.to_ne_bytes()); }
        out
    }
}
