/// Socket message flags from Linux UAPI. ABI shims cast only when writing a
/// narrower `msghdr.msg_flags` field.
pub const MSG_PEEK: u64 = 0x02;
pub const MSG_CTRUNC: u64 = 0x08;
pub const MSG_TRUNC: u64 = 0x20;
pub const MSG_DONTWAIT: u64 = 0x40;
pub const MSG_EOR: u64 = 0x80;
pub const MSG_WAITALL: u64 = 0x100;
pub const MSG_NOSIGNAL: u64 = 0x4000;
pub const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;

/// Linux `shutdown(2)` direction values.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ShutdownHow { Read, Write, ReadWrite }

impl TryFrom<u32> for ShutdownHow {
    type Error = ();

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        match raw { 0 => Ok(Self::Read), 1 => Ok(Self::Write), 2 => Ok(Self::ReadWrite), _ => Err(()) }
    }
}
