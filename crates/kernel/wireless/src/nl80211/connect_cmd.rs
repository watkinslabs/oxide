// PLACEHOLDER: command handlers for this group are not written yet. Every
// entry answers `EOPNOTSUPP`, which is what a family reports for a command it
// admits and cannot serve.

extern crate alloc;

use alloc::vec::Vec;

use netlink::genetlink::family::GenlCtx;
use netlink::Nlmsghdr;
use syscall::errno::Errno;

use super::msg;

/// Not served yet. # C: O(1)
pub fn connect(hdr: &Nlmsghdr, _attrs: &[u8], _ctx: GenlCtx) -> Vec<u8> {
    msg::error(hdr, Errno::Eopnotsupp)
}

/// Not served yet. # C: O(1)
pub fn disconnect(hdr: &Nlmsghdr, _attrs: &[u8], _ctx: GenlCtx) -> Vec<u8> {
    msg::error(hdr, Errno::Eopnotsupp)
}

/// Not served yet. # C: O(1)
pub fn authenticate(hdr: &Nlmsghdr, _attrs: &[u8], _ctx: GenlCtx) -> Vec<u8> {
    msg::error(hdr, Errno::Eopnotsupp)
}

/// Not served yet. # C: O(1)
pub fn associate(hdr: &Nlmsghdr, _attrs: &[u8], _ctx: GenlCtx) -> Vec<u8> {
    msg::error(hdr, Errno::Eopnotsupp)
}

/// Not served yet. # C: O(1)
pub fn deauthenticate(hdr: &Nlmsghdr, _attrs: &[u8], _ctx: GenlCtx) -> Vec<u8> {
    msg::error(hdr, Errno::Eopnotsupp)
}

/// Not served yet. # C: O(1)
pub fn disassociate(hdr: &Nlmsghdr, _attrs: &[u8], _ctx: GenlCtx) -> Vec<u8> {
    msg::error(hdr, Errno::Eopnotsupp)
}
