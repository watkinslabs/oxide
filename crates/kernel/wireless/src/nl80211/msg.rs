// Message framing for nl80211 replies and events, and the attribute writers
// every command shares.
//
// A reply is a `nlmsghdr`, a `genlmsghdr`, then attributes. Nothing here
// decides anything; it exists so no command builds a header by hand and gets
// the length or the sequence number wrong.

extern crate alloc;

use alloc::vec::Vec;

use netlink::genetlink::attr;
use netlink::Nlmsghdr;
use syscall::errno::Errno;

use crate::ieee80211::MacAddr;
use crate::uapi::{attr as a, cmd, NL80211_FAMILY_VERSION};

/// Start a reply carrying one command's attributes. # C: O(1)
pub fn start(hdr: &Nlmsghdr, cmd: u8) -> Vec<u8> {
    netlink::genetlink::message::start(hdr.nlmsg_pid, hdr.nlmsg_seq, super::family::family_id(),
                                       NL80211_FAMILY_VERSION, 0, cmd)
}

/// Finish a message, writing its length. # C: O(1)
pub fn end(out: &mut Vec<u8>) { netlink::genetlink::message::end(out, 0); }

/// Append one finished message to a multi-part dump, marking it as a part.
/// # C: O(len)
pub fn push(reply: &mut Vec<u8>, body: Vec<u8>) {
    netlink::genetlink::message::push_multi(reply, body);
}

/// Close a multi-part dump. Without the terminator a reader blocks forever
/// waiting for a part that never comes. # C: O(1)
pub fn push_done(reply: &mut Vec<u8>, hdr: &Nlmsghdr) {
    netlink::genetlink::message::push_done(reply, hdr.nlmsg_seq, hdr.nlmsg_pid);
}

/// A bare error or acknowledgement reply. # C: O(1)
pub fn error(hdr: &Nlmsghdr, err: Errno) -> Vec<u8> {
    netlink::genetlink::message::error(hdr, Err(err))
}

/// A bare success acknowledgement. # C: O(1)
pub fn ack(hdr: &Nlmsghdr) -> Vec<u8> { netlink::genetlink::message::error(hdr, Ok(())) }

/// Append a station address. # C: O(1)
pub fn put_mac(out: &mut Vec<u8>, ty: u16, mac: MacAddr) { attr::put(out, ty, &mac.0); }

/// Append a `u8` attribute. # C: O(1)
pub fn put_u8(out: &mut Vec<u8>, ty: u16, v: u8) { attr::put(out, ty, &[v]); }

/// Append an `i32` attribute. # C: O(1)
pub fn put_i32(out: &mut Vec<u8>, ty: u16, v: i32) { attr::put(out, ty, &v.to_ne_bytes()); }

/// Append a `u64` attribute with the padding attribute netlink needs to keep
/// the payload eight-byte aligned.
///
/// The padding attribute's NUMBER is per-namespace: the top-level padding type
/// is a different number inside the network report, the station report, the
/// survey and the per-identifier counters. It is a parameter and not a
/// constant because writing the top-level number inside a nest emits an
/// attribute the reader interprets as something else entirely. # C: O(1)
pub fn put_u64(out: &mut Vec<u8>, ty: u16, v: u64, pad_ty: u16) {
    attr::put_u64_64bit(out, ty, v, pad_ty);
}

/// Append a flag attribute — present means true, absent means false. A flag
/// written with a zero payload is still TRUE on the wire, which is why a
/// caller must not write one for a false value. # C: O(1)
pub fn put_flag(out: &mut Vec<u8>, ty: u16) { attr::put(out, ty, &[]); }

/// Read a `u8` attribute. # C: O(N attrs)
pub fn get_u8(attrs: &[u8], ty: u16) -> Option<u8> {
    attr::find(attrs, ty).and_then(|a| a.payload.first().copied())
}

/// Read a `u16` attribute. # C: O(N attrs)
pub fn get_u16(attrs: &[u8], ty: u16) -> Option<u16> {
    let a = attr::find(attrs, ty)?;
    Some(u16::from_ne_bytes(a.payload.get(..2)?.try_into().ok()?))
}

/// Read a `u32` attribute. # C: O(N attrs)
pub fn get_u32(attrs: &[u8], ty: u16) -> Option<u32> {
    let a = attr::find(attrs, ty)?;
    Some(u32::from_ne_bytes(a.payload.get(..4)?.try_into().ok()?))
}

/// Read a `u64` attribute. # C: O(N attrs)
pub fn get_u64(attrs: &[u8], ty: u16) -> Option<u64> {
    let a = attr::find(attrs, ty)?;
    Some(u64::from_ne_bytes(a.payload.get(..8)?.try_into().ok()?))
}

/// Read an address attribute. An attribute of the wrong width is absent, not
/// truncated: a five-byte address is not an address. # C: O(N attrs)
pub fn get_mac(attrs: &[u8], ty: u16) -> Option<MacAddr> {
    let a = attr::find(attrs, ty)?;
    if a.payload.len() != crate::ieee80211::ADDR_LEN { return None; }
    MacAddr::from_slice(a.payload)
}

/// Read a byte-string attribute. # C: O(N attrs)
pub fn get_bytes<'a>(attrs: &'a [u8], ty: u16) -> Option<&'a [u8]> {
    attr::find(attrs, ty).map(|a| a.payload)
}

/// Read a NUL-terminated string attribute. # C: O(N attrs)
pub fn get_str(attrs: &[u8], ty: u16) -> Option<&str> {
    let a = attr::find(attrs, ty)?;
    let end = a.payload.iter().position(|&b| b == 0).unwrap_or(a.payload.len());
    core::str::from_utf8(&a.payload[..end]).ok()
}

/// Whether a flag attribute is present. # C: O(N attrs)
pub fn get_flag(attrs: &[u8], ty: u16) -> bool { attr::find(attrs, ty).is_some() }

/// Read a nested list of `u32` values, as the cipher-suite and frequency
/// attributes carry them: a flat array, not a nest. # C: O(len)
pub fn get_u32_array(attrs: &[u8], ty: u16) -> Vec<u32> {
    let Some(a) = attr::find(attrs, ty) else { return Vec::new(); };
    a.payload.chunks_exact(4)
        .map(|c| u32::from_ne_bytes([c[0], c[1], c[2], c[3]])).collect()
}

/// Append a flat array of `u32` values. # C: O(len)
pub fn put_u32_array(out: &mut Vec<u8>, ty: u16, values: &[u32]) {
    let mut payload = Vec::with_capacity(values.len() * 4);
    for v in values { payload.extend_from_slice(&v.to_ne_bytes()); }
    attr::put(out, ty, &payload);
}

/// Command number carried in a message this module built. Used by tests and
/// by the event fan-out to check what it is sending. # C: O(1)
pub fn message_cmd(msg: &[u8]) -> Option<u8> {
    msg.get(Nlmsghdr::SIZE).copied()
}

/// Whether a built message is one of the interface commands, for a reader
/// that dispatches on command rather than re-parsing. # C: O(1)
pub fn is_cmd(msg: &[u8], want: u8) -> bool { message_cmd(msg) == Some(want) }

/// The command a request asked for. # C: O(1)
pub fn request_cmd(full_msg: &[u8]) -> Option<u8> { message_cmd(full_msg) }

/// Every nl80211 command this build serves, for the controller's report and
/// for the `SUPPORTED_COMMANDS` attribute a radio advertises.
pub const SUPPORTED_COMMANDS: &[u8] = &[
    cmd::GET_WIPHY, cmd::SET_WIPHY,
    cmd::GET_INTERFACE, cmd::SET_INTERFACE, cmd::NEW_INTERFACE, cmd::DEL_INTERFACE,
    cmd::GET_KEY, cmd::SET_KEY, cmd::NEW_KEY, cmd::DEL_KEY,
    cmd::START_AP, cmd::STOP_AP, cmd::SET_BSS,
    cmd::GET_STATION, cmd::SET_STATION, cmd::NEW_STATION, cmd::DEL_STATION,
    cmd::GET_REG, cmd::SET_REG, cmd::REQ_SET_REG,
    cmd::GET_SCAN, cmd::TRIGGER_SCAN, cmd::ABORT_SCAN,
    cmd::AUTHENTICATE, cmd::ASSOCIATE, cmd::DEAUTHENTICATE, cmd::DISASSOCIATE,
    cmd::CONNECT, cmd::DISCONNECT,
    cmd::GET_SURVEY,
    cmd::SET_PMKSA, cmd::DEL_PMKSA, cmd::FLUSH_PMKSA,
    cmd::REGISTER_FRAME, cmd::FRAME, cmd::FRAME_WAIT_CANCEL,
    cmd::SET_POWER_SAVE, cmd::GET_POWER_SAVE,
    cmd::SET_CQM, cmd::SET_CHANNEL,
    cmd::GET_PROTOCOL_FEATURES,
];
