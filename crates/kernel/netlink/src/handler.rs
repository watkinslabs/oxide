extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::Nlmsghdr;

/// Function signature for an external protocol handler. Receives
/// one nlmsghdr-prefixed request buffer, returns the reply bytes
/// to push onto the socket's RX queue. Used by NETLINK_NETFILTER
/// (and any future protocol whose handler lives in a sibling
/// crate) — netlink can't depend on those crates directly without
/// circular deps, so they install their handler here.
pub type ProtoHandler = fn(&[u8]) -> Vec<u8>;

static NETFILTER_HANDLER: AtomicPtr<()> =
    AtomicPtr::new(core::ptr::null_mut());

/// Install the NETLINK_NETFILTER protocol handler. Idempotent;
/// the netfilter crate calls this once at boot. # C: O(1)
pub fn install_netfilter_handler(f: ProtoHandler) {
    NETFILTER_HANDLER.store(f as *mut (), Ordering::Release);
}

pub(crate) fn invoke_netfilter(msg: &[u8]) -> Vec<u8> {
    let raw = NETFILTER_HANDLER.load(Ordering::Acquire);
    if raw.is_null() {
        if let Some(hdr) = Nlmsghdr::parse(msg) {
            let mut done = alloc::vec![0u8; Nlmsghdr::SIZE];
            Nlmsghdr::done(hdr.nlmsg_seq, hdr.nlmsg_pid).write_to(&mut done);
            return done;
        }
        return Vec::new();
    }
    // SAFETY: raw was installed via install_netfilter_handler with
    // the documented `fn(&[u8]) -> Vec<u8>` signature.
    let f: ProtoHandler = unsafe { core::mem::transmute(raw) };
    f(msg)
}
