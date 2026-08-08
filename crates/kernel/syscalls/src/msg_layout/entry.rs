// Which ABI a message syscall's caller speaks, and the admission rule that
// turns that plus the caller's flags into exactly one [`MsgLayout`].

use syscall::errno::Errno;

use net::uapi::MSG_CMSG_COMPAT;

use super::MsgLayout;

/// Which entry point a message syscall arrived through.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EntryAbi {
    /// The ordinary 64-bit entry. `MSG_CMSG_COMPAT` is not a flag userspace
    /// may set here.
    #[default]
    Native,
    /// The 32-bit entry, which sets `MSG_CMSG_COMPAT` on the caller's behalf
    /// and therefore always speaks the compat layout.
    Compat,
}

impl EntryAbi {
    /// The flags one entry hands the shared body: the compat entry ORs in the
    /// bit that records the layout for the rest of the call, exactly as the
    /// native entry refuses it. # C: O(1)
    pub const fn flags(self, flags: u64) -> u64 {
        match self { Self::Native => flags, Self::Compat => flags | MSG_CMSG_COMPAT }
    }
}

/// The single compat decision. A native caller that sets `MSG_CMSG_COMPAT`
/// gets EINVAL — before the descriptor, the timeout, or any user memory is
/// touched, because the flag says the whole call was parsed wrong. A compat
/// caller always gets the 32-bit layout, whether or not the bit survived the
/// entry that set it.
///
/// Every decoder takes the returned value. Nothing downstream re-reads the
/// flag to pick a shape: that split is what let one caller change the parsed
/// layout while the guard meant to prevent it sat unreachable (B1641).
/// # C: O(1)
pub const fn layout(flags: u64, abi: EntryAbi) -> Result<MsgLayout, Errno> {
    match abi {
        EntryAbi::Compat => Ok(MsgLayout::Compat),
        EntryAbi::Native => {
            if flags & MSG_CMSG_COMPAT != 0 { Err(Errno::Einval) } else { Ok(MsgLayout::Native) }
        }
    }
}

/// The same decision as a negative errno, for the ABI shims that report one.
/// # C: O(1)
pub fn layout_or_errno(flags: u64, abi: EntryAbi) -> Result<MsgLayout, i64> {
    layout(flags, abi).map_err(|e| -(e.as_i32() as i64))
}

/// `msg_flags` as a receive publishes it. The compat bit is kernel
/// bookkeeping and never reaches the caller's `msghdr`. # C: O(1)
pub const fn published_flags(flags: u32) -> u32 { flags & !(MSG_CMSG_COMPAT as u32) }
