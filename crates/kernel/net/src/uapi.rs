/// Socket message flags from Linux UAPI. ABI shims cast only when writing a
/// narrower `msghdr.msg_flags` field.
pub const MSG_PEEK: u64 = 0x02;
pub const MSG_CTRUNC: u64 = 0x08;
pub const MSG_TRUNC: u64 = 0x20;
pub const MSG_DONTWAIT: u64 = 0x40;
pub const MSG_NOSIGNAL: u64 = 0x4000;
