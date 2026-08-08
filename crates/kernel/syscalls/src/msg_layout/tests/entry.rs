// The compat admission rule: who may speak the 32-bit layout, and what a
// caller that may not is told.

use syscall::errno::Errno;

use net::uapi::{MSG_CMSG_CLOEXEC, MSG_CMSG_COMPAT, MSG_DONTWAIT, MSG_PEEK};

use crate::msg_layout::{EntryAbi, MsgLayout, entry::{layout, layout_or_errno, published_flags}};

#[test]
fn a_native_caller_may_not_set_the_compat_flag() {
    assert_eq!(layout(MSG_CMSG_COMPAT, EntryAbi::Native), Err(Errno::Einval));
    assert_eq!(layout(MSG_CMSG_COMPAT | MSG_DONTWAIT, EntryAbi::Native), Err(Errno::Einval));
    assert_eq!(layout_or_errno(MSG_CMSG_COMPAT, EntryAbi::Native),
        Err(-(Errno::Einval.as_i32() as i64)));
}

#[test]
fn every_other_flag_leaves_a_native_caller_native() {
    for flags in [0, MSG_DONTWAIT, MSG_PEEK, MSG_CMSG_CLOEXEC,
        MSG_DONTWAIT | MSG_PEEK | MSG_CMSG_CLOEXEC]
    {
        assert_eq!(layout(flags, EntryAbi::Native), Ok(MsgLayout::Native), "flags={flags:#x}");
    }
}

#[test]
fn the_compat_entry_always_speaks_the_compat_layout() {
    assert_eq!(layout(MSG_CMSG_COMPAT, EntryAbi::Compat), Ok(MsgLayout::Compat));
    // The flag records the entry; it does not decide it. A compat caller
    // reaches the 32-bit shape whether or not the bit arrived with it, which
    // is why nothing downstream may re-read the flag to pick a layout.
    assert_eq!(layout(0, EntryAbi::Compat), Ok(MsgLayout::Compat));
    assert_eq!(layout(MSG_PEEK, EntryAbi::Compat), Ok(MsgLayout::Compat));
}

#[test]
fn the_compat_entry_sets_the_flag_its_native_twin_refuses() {
    assert_eq!(EntryAbi::Compat.flags(MSG_PEEK), MSG_PEEK | MSG_CMSG_COMPAT);
    assert_eq!(EntryAbi::Native.flags(MSG_PEEK), MSG_PEEK);
    // Round trip: what the compat entry produces is exactly what the native
    // entry rejects, and what the compat layout rule accepts.
    let flags = EntryAbi::Compat.flags(0);
    assert_eq!(layout(flags, EntryAbi::Native), Err(Errno::Einval));
    assert_eq!(layout(flags, EntryAbi::Compat), Ok(MsgLayout::Compat));
}

#[test]
fn the_compat_bit_is_never_published_back_to_the_caller() {
    assert_eq!(published_flags(MSG_CMSG_COMPAT as u32), 0);
    assert_eq!(published_flags(MSG_CMSG_COMPAT as u32 | MSG_CMSG_CLOEXEC as u32),
        MSG_CMSG_CLOEXEC as u32);
    assert_eq!(published_flags(MSG_PEEK as u32), MSG_PEEK as u32);
}
