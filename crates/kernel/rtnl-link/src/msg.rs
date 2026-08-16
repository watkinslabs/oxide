//! Reading a link message: the fixed header, the outer attributes, and the
//! `IFLA_LINKINFO` envelope that names the kind.

extern crate alloc;

use syscall::errno::Errno;

use crate::nla::{self, Attr};
use crate::uapi::*;

/// The fixed part of a link message.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IfInfo {
    pub family: u8,
    pub dev_type: u16,
    pub index: i32,
    pub flags: u32,
    pub change: u32,
}

/// A parsed link message.
#[derive(Copy, Clone, Debug, Default)]
pub struct LinkMsg<'a> {
    pub info: IfInfo,
    /// Attribute blob following the fixed header.
    pub attrs: &'a [u8],
    pub name: Option<&'a str>,
    pub mtu: Option<u32>,
    /// The lower device a stacked kind is built on.
    pub link: Option<u32>,
    /// The master a slave is being enslaved to.
    pub master: Option<u32>,
    pub address: Option<&'a [u8]>,
    /// Kind string from inside `IFLA_LINKINFO`.
    pub kind: Option<&'a str>,
    /// Kind-private attribute blob.
    pub data: Option<&'a [u8]>,
    /// Slave-side kind and data, for enslaving into a master.
    pub slave_kind: Option<&'a str>,
    pub slave_data: Option<&'a [u8]>,
}

/// Parse a link message body: the fixed header plus every attribute this crate
/// or a kind needs. A body shorter than the fixed header is `EINVAL`.
/// # C: O(len(body))
pub fn parse(body: &[u8]) -> Result<LinkMsg<'_>, Errno> {
    if body.len() < IFINFOMSG_LEN { return Err(Errno::Einval); }
    let info = IfInfo {
        family: body[IFI_FAMILY_OFF],
        dev_type: u16::from_ne_bytes([body[IFI_TYPE_OFF], body[IFI_TYPE_OFF + 1]]),
        index: i32::from_ne_bytes([body[IFI_INDEX_OFF], body[IFI_INDEX_OFF + 1],
                                   body[IFI_INDEX_OFF + 2], body[IFI_INDEX_OFF + 3]]),
        flags: u32::from_ne_bytes([body[IFI_FLAGS_OFF], body[IFI_FLAGS_OFF + 1],
                                   body[IFI_FLAGS_OFF + 2], body[IFI_FLAGS_OFF + 3]]),
        change: u32::from_ne_bytes([body[IFI_CHANGE_OFF], body[IFI_CHANGE_OFF + 1],
                                    body[IFI_CHANGE_OFF + 2], body[IFI_CHANGE_OFF + 3]]),
    };
    let attrs = &body[IFINFOMSG_LEN..];
    let mut out = LinkMsg { info, attrs, ..Default::default() };
    let mut bad = None;
    nla::for_each(attrs, |a: Attr<'_>| {
        match a.ty {
            IFLA_IFNAME if out.name.is_none() => match a.cstr() {
                Some(s) if !s.is_empty() && s.len() < IFNAMSIZ => out.name = Some(s),
                _ => bad = Some(Errno::Einval),
            },
            IFLA_MTU if out.mtu.is_none() => match a.u32() {
                Some(v) => out.mtu = Some(v),
                None => bad = Some(Errno::Einval),
            },
            IFLA_LINK if out.link.is_none() => match a.u32() {
                Some(v) => out.link = Some(v),
                None => bad = Some(Errno::Einval),
            },
            IFLA_MASTER if out.master.is_none() => match a.u32() {
                Some(v) => out.master = Some(v),
                None => bad = Some(Errno::Einval),
            },
            IFLA_ADDRESS if out.address.is_none() => out.address = Some(a.payload),
            IFLA_LINKINFO => parse_linkinfo(a.payload, &mut out, &mut bad),
            _ => {}
        }
    });
    match bad { Some(e) => Err(e), None => Ok(out) }
}

fn parse_linkinfo<'a>(blob: &'a [u8], out: &mut LinkMsg<'a>, bad: &mut Option<Errno>) {
    nla::for_each(blob, |a: Attr<'a>| {
        match a.ty {
            IFLA_INFO_KIND if out.kind.is_none() => match a.cstr() {
                Some(s) if !s.is_empty() && s.len() < MODULE_NAME_LEN => out.kind = Some(s),
                _ => *bad = Some(Errno::Einval),
            },
            IFLA_INFO_DATA if out.data.is_none() => out.data = Some(a.payload),
            IFLA_INFO_SLAVE_KIND if out.slave_kind.is_none() => match a.cstr() {
                Some(s) if !s.is_empty() && s.len() < MODULE_NAME_LEN =>
                    out.slave_kind = Some(s),
                _ => *bad = Some(Errno::Einval),
            },
            IFLA_INFO_SLAVE_DATA if out.slave_data.is_none() => out.slave_data = Some(a.payload),
            _ => {}
        }
    });
}

/// Encode an `IFLA_LINKINFO` envelope for a dump reply. # C: O(len(data))
pub fn put_linkinfo(out: &mut alloc::vec::Vec<u8>, kind: &str, data: Option<&[u8]>) {
    let at = nla::nest_start(out, IFLA_LINKINFO);
    let mut name = alloc::vec::Vec::with_capacity(kind.len() + 1);
    name.extend_from_slice(kind.as_bytes());
    name.push(0);
    nla::put(out, IFLA_INFO_KIND, &name);
    if let Some(d) = data {
        let inner = nla::nest_start(out, IFLA_INFO_DATA);
        out.extend_from_slice(d);
        nla::nest_end(out, inner);
    }
    nla::nest_end(out, at);
}
