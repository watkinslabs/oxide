// Strict validation of rtnetlink DUMP requests.
//
// A netlink dump request carries a header whose fields the old code path
// ignored entirely. Under `NETLINK_GET_STRICT_CHK` the reference validates
// that header and honours the one filter it defines, so a client that asks
// for a single device's addresses receives that device's addresses instead of
// the whole namespace's. Pure decisions, no target gate: the callers are the
// dump builders, and every rule below is covered hosted.

use syscall::errno::Errno;

use super::uapi::{ifa, Ifaddrmsg, Ifinfomsg};
use crate::Nlmsghdr;

/// Whether a request selected the dump handler rather than a one-shot handler.
/// # C: O(1)
pub fn is_dump(req: &Nlmsghdr) -> bool {
    req.nlmsg_flags & crate::flags::NLM_F_DUMP == crate::flags::NLM_F_DUMP
}

/// `NLM_F_DUMP_FILTERED`: the answer covers only what the request asked for.
pub const NLM_F_DUMP_FILTERED: u16 = 0x20;

/// Outcome of validating a `RTM_GETLINK` dump request.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LinkDump {
    /// Walk every device.
    All,
    /// Walk a caller-mapped peer namespace.
    Target(i32),
    /// Refuse the request.
    Err(Errno),
}

/// Outcome of validating a `RTM_GETADDR` dump request.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AddrDump {
    /// Report every address in the namespace.
    All,
    /// Report only the named device's addresses, and mark the answer filtered.
    OneDevice(u32),
    /// Report a caller-mapped peer namespace, optionally narrowed to one device.
    Target { nsid: i32, ifindex: Option<u32> },
    /// Refuse the request.
    Err(Errno),
}

/// The `nlmsghdr` payload of a request, or `None` when the message is shorter
/// than the family header the type requires. # C: O(1)
fn payload(full_msg: &[u8], want: usize) -> Option<&[u8]> {
    let off = Nlmsghdr::SIZE;
    if full_msg.len() < off + want { return None; }
    Some(&full_msg[off..])
}

/// Strict address-dump attributes have one defined key. Its caller-local ID is
/// resolved by the socket namespace owner after this grammar check. # C: O(N attrs)
fn validate_addr_dump_attrs(attrs: &[u8]) -> Result<Option<i32>, Errno> {
    let mut off = 0;
    let mut target = None;
    while off < attrs.len() {
        if attrs.len() - off < 4 { return Err(Errno::Einval); }
        let len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let ty = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if len < 4 || len > attrs.len() - off { return Err(Errno::Einval); }
        let next = (len + 3) & !3;
        if next > attrs.len() - off { return Err(Errno::Einval); }
        if ty != ifa::IFA_TARGET_NETNSID || len != 8 || target.is_some() {
            return Err(Errno::Einval);
        }
        target = Some(i32::from_ne_bytes(attrs[off + 4..off + 8].try_into().unwrap()));
        off = next;
    }
    Ok(target)
}

/// Validate a `RTM_GETLINK` dump request.
///
/// Link dumps take no device filter: the reference rejects a non-zero
/// `ifi_index` outright rather than silently ignoring it, so a client that
/// filters the wrong way learns it instead of receiving every device.
/// # C: O(1)
pub fn validate_link_dump(strict: bool, full_msg: &[u8]) -> LinkDump {
    if !strict { return link_target_nsid(full_msg).map_or(LinkDump::All, LinkDump::Target); }
    let Some(body) = payload(full_msg, Ifinfomsg::SIZE) else { return LinkDump::Err(Errno::Einval) };
    let pad = body[1];
    let ifi_type = u16::from_ne_bytes([body[2], body[3]]);
    let ifi_index = i32::from_ne_bytes([body[4], body[5], body[6], body[7]]);
    let ifi_flags = u32::from_ne_bytes([body[8], body[9], body[10], body[11]]);
    let ifi_change = u32::from_ne_bytes([body[12], body[13], body[14], body[15]]);
    if pad != 0 || ifi_type != 0 || ifi_flags != 0 || ifi_change != 0 { return LinkDump::Err(Errno::Einval); }
    if ifi_index != 0 { return LinkDump::Err(Errno::Einval); }
    match link_target_strict(&body[Ifinfomsg::SIZE..]) {
        Ok(Some(nsid)) => LinkDump::Target(nsid),
        Ok(None) => LinkDump::All,
        Err(e) => LinkDump::Err(e),
    }
}

/// Caller-local target namespace from a complete link request. # C: O(N attrs)
pub(crate) fn link_target_nsid(full_msg: &[u8]) -> Option<i32> {
    payload(full_msg, Ifinfomsg::SIZE).and_then(|body| link_target(&body[Ifinfomsg::SIZE..]))
}

fn link_target(attrs: &[u8]) -> Option<i32> {
    let mut off = 0;
    let mut target = None;
    while off < attrs.len() {
        if attrs.len() - off < 4 { return None; }
        let len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let ty = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if len < 4 || len > attrs.len() - off { return None; }
        let next = (len + 3) & !3;
        if next > attrs.len() - off { return None; }
        if ty == super::uapi::ifla::IFLA_TARGET_NETNSID && len == 8 {
            target = Some(i32::from_ne_bytes(attrs[off + 4..off + 8].try_into().unwrap()));
        }
        off = next;
    }
    target
}

fn link_target_strict(attrs: &[u8]) -> Result<Option<i32>, Errno> {
    let mut off = 0;
    let mut target = None;
    while off < attrs.len() {
        if attrs.len() - off < 4 { return Err(Errno::Einval); }
        let len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let ty = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if len < 4 || len > attrs.len() - off { return Err(Errno::Einval); }
        let next = (len + 3) & !3;
        if next > attrs.len() - off { return Err(Errno::Einval); }
        if ty != super::uapi::ifla::IFLA_TARGET_NETNSID || len != 8 || target.is_some() {
            return Err(Errno::Einval);
        }
        target = Some(i32::from_ne_bytes(attrs[off + 4..off + 8].try_into().unwrap()));
        off = next;
    }
    Ok(target)
}

/// Validate a `RTM_GETADDR` dump request and extract its device filter.
///
/// The header's `ifa_index` is the filter; `ifa_prefixlen`, `ifa_flags` and
/// `ifa_scope` carry no meaning in a dump request and must be zero.
/// # C: O(1)
pub fn validate_addr_dump(strict: bool, full_msg: &[u8]) -> AddrDump {
    if !strict { return AddrDump::All; }
    let Some(body) = payload(full_msg, Ifaddrmsg::SIZE) else { return AddrDump::Err(Errno::Einval) };
    let prefixlen = body[1];
    let flags = body[2];
    let scope = body[3];
    let index = u32::from_ne_bytes([body[4], body[5], body[6], body[7]]);
    if prefixlen != 0 || flags != 0 || scope != 0 { return AddrDump::Err(Errno::Einval); }
    let target = match validate_addr_dump_attrs(&body[Ifaddrmsg::SIZE..]) {
        Ok(target) => target, Err(e) => return AddrDump::Err(e),
    };
    if let Some(nsid) = target {
        AddrDump::Target { nsid, ifindex: (index != 0).then_some(index) }
    } else if index != 0 { AddrDump::OneDevice(index) } else { AddrDump::All }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;

    fn msg(body: &[u8]) -> alloc::vec::Vec<u8> {
        let mut m = alloc::vec![0u8; Nlmsghdr::SIZE];
        m.extend_from_slice(body);
        m
    }

    fn ifinfo(index: i32, flags: u32, change: u32, ifi_type: u16) -> alloc::vec::Vec<u8> {
        let mut b = alloc::vec![0u8; Ifinfomsg::SIZE];
        b[2..4].copy_from_slice(&ifi_type.to_ne_bytes());
        b[4..8].copy_from_slice(&index.to_ne_bytes());
        b[8..12].copy_from_slice(&flags.to_ne_bytes());
        b[12..16].copy_from_slice(&change.to_ne_bytes());
        b
    }

    fn ifaddr(prefixlen: u8, flags: u8, scope: u8, index: u32) -> alloc::vec::Vec<u8> {
        let mut b = alloc::vec![0u8; Ifaddrmsg::SIZE];
        b[1] = prefixlen; b[2] = flags; b[3] = scope;
        b[4..8].copy_from_slice(&index.to_ne_bytes());
        b
    }

    fn attr(ty: u16, value: &[u8]) -> alloc::vec::Vec<u8> {
        let mut a = alloc::vec::Vec::new();
        a.extend_from_slice(&(4 + value.len() as u16).to_ne_bytes());
        a.extend_from_slice(&ty.to_ne_bytes());
        a.extend_from_slice(value);
        while a.len() % 4 != 0 { a.push(0); }
        a
    }

    #[test]
    fn a_lax_dump_accepts_anything_including_a_truncated_header() {
        // Without the option the reference keeps answering the requests it
        // always answered, header contents and all.
        assert_eq!(validate_link_dump(false, &msg(&ifinfo(7, 1, 1, 3))), LinkDump::All);
        assert_eq!(validate_addr_dump(false, &msg(&ifaddr(24, 8, 253, 7))), AddrDump::All);
        assert_eq!(validate_link_dump(false, &[]), LinkDump::All);
        assert_eq!(validate_addr_dump(false, &[]), AddrDump::All);
    }

    #[test]
    fn a_strict_dump_needs_a_whole_family_header() {
        assert_eq!(validate_link_dump(true, &[]), LinkDump::Err(Errno::Einval));
        assert_eq!(validate_addr_dump(true, &[]), AddrDump::Err(Errno::Einval));
        let short = msg(&alloc::vec![0u8; Ifinfomsg::SIZE - 1]);
        assert_eq!(validate_link_dump(true, &short), LinkDump::Err(Errno::Einval));
    }

    #[test]
    fn a_clean_strict_request_dumps_everything() {
        assert_eq!(validate_link_dump(true, &msg(&ifinfo(0, 0, 0, 0))), LinkDump::All);
        assert_eq!(validate_addr_dump(true, &msg(&ifaddr(0, 0, 0, 0))), AddrDump::All);
    }

    #[test]
    fn a_link_dump_refuses_a_device_filter_rather_than_ignoring_it() {
        // Silently ignoring it answers "every device" to a request that asked
        // for one, which reads as though the filter worked.
        assert_eq!(validate_link_dump(true, &msg(&ifinfo(2, 0, 0, 0))), LinkDump::Err(Errno::Einval));
    }

    #[test]
    fn a_link_dump_refuses_a_dirty_header() {
        for dirty in [ifinfo(0, 1, 0, 0), ifinfo(0, 0, 1, 0), ifinfo(0, 0, 0, 1)] {
            assert_eq!(validate_link_dump(true, &msg(&dirty)), LinkDump::Err(Errno::Einval));
        }
        let mut pad = ifinfo(0, 0, 0, 0);
        pad[1] = 1;
        assert_eq!(validate_link_dump(true, &msg(&pad)), LinkDump::Err(Errno::Einval));
    }

    #[test]
    fn an_address_dump_honours_its_device_filter() {
        assert_eq!(validate_addr_dump(true, &msg(&ifaddr(0, 0, 0, 2))), AddrDump::OneDevice(2));
        assert_eq!(validate_addr_dump(true, &msg(&ifaddr(0, 0, 0, u32::MAX))),
            AddrDump::OneDevice(u32::MAX));
    }

    #[test]
    fn an_address_dump_refuses_a_header_field_that_has_no_meaning_in_a_request() {
        for dirty in [ifaddr(24, 0, 0, 0), ifaddr(0, 8, 0, 0), ifaddr(0, 0, 253, 0)] {
            assert_eq!(validate_addr_dump(true, &msg(&dirty)), AddrDump::Err(Errno::Einval));
        }
        // A dirty field is refused even when a filter is also present.
        assert_eq!(validate_addr_dump(true, &msg(&ifaddr(24, 0, 0, 2))), AddrDump::Err(Errno::Einval));
    }

    #[test]
    fn a_strict_address_dump_refuses_unknown_or_malformed_attributes() {
        let mut body = ifaddr(0, 0, 0, 0);
        body.extend_from_slice(&attr(0x7fff, &[1]));
        assert_eq!(validate_addr_dump(true, &msg(&body)), AddrDump::Err(Errno::Einval));
        let mut target = ifaddr(0, 0, 0, 0);
        target.extend_from_slice(&attr(ifa::IFA_TARGET_NETNSID, &7i32.to_ne_bytes()));
        assert_eq!(validate_addr_dump(true, &msg(&target)), AddrDump::Target { nsid: 7, ifindex: None });
        let mut truncated = ifaddr(0, 0, 0, 0);
        truncated.extend_from_slice(&[8, 0, 1, 0, 1]);
        assert_eq!(validate_addr_dump(true, &msg(&truncated)), AddrDump::Err(Errno::Einval));
    }

    #[test]
    fn the_filtered_answer_flag_is_the_uapi_bit() {
        assert_eq!(NLM_F_DUMP_FILTERED, 0x20);
        // Distinct from every flag the request side already uses.
        for other in [crate::flags::NLM_F_REQUEST, crate::flags::NLM_F_MULTI,
                      crate::flags::NLM_F_ACK, crate::flags::NLM_F_ECHO,
                      crate::flags::NLM_F_DUMP_INTR, crate::flags::NLM_F_ROOT,
                      crate::flags::NLM_F_MATCH, crate::flags::NLM_F_ATOMIC] {
            assert_ne!(NLM_F_DUMP_FILTERED, other);
        }
    }
}
