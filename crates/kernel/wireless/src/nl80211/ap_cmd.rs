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
pub fn start(hdr: &Nlmsghdr, _attrs: &[u8], _ctx: GenlCtx) -> Vec<u8> {
    msg::error(hdr, Errno::Eopnotsupp)
}

/// Not served yet. # C: O(1)
pub fn stop(hdr: &Nlmsghdr, _attrs: &[u8], _ctx: GenlCtx) -> Vec<u8> {
    msg::error(hdr, Errno::Eopnotsupp)
}

/// Not served yet. # C: O(1)
pub fn set_bss(hdr: &Nlmsghdr, _attrs: &[u8], _ctx: GenlCtx) -> Vec<u8> {
    msg::error(hdr, Errno::Eopnotsupp)
}
