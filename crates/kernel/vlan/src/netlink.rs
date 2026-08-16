// The `vlan` link kind's rtnetlink surface: read the attribute blob, refuse
// what cannot work, and hand back a request the interface layer can act on.

extern crate alloc;
use alloc::vec::Vec;

use net::addr::{MacAddr, NetIfaceId};
use syscall::errno::Errno;

use crate::caps::{check_real_dev, max_mtu, RealDevCaps};
use crate::dev::VlanDev;
use crate::flags::{known, VLAN_FLAG_DEFAULT};
use crate::nla;
use crate::registry::{VlanKey, VlanTable};
use crate::uapi::{
    ETH_ALEN, ETH_P_8021AD, ETH_P_8021Q, IFLA_ADDRESS, IFLA_LINK, IFLA_MTU,
    IFLA_VLAN_EGRESS_QOS, IFLA_VLAN_FLAGS, IFLA_VLAN_FLAGS_LEN, IFLA_VLAN_ID,
    IFLA_VLAN_INGRESS_QOS, IFLA_VLAN_PROTOCOL, IFLA_VLAN_QOS_MAPPING,
    IFLA_VLAN_QOS_MAPPING_LEN, NLA_HDR_LEN, NLA_U16_LEN, VLAN_VID_MASK,
};

/// A `{flags, mask}` change request.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct FlagsRequest { pub flags: u32, pub mask: u32 }

/// One priority translation. The two fields swap meaning between the ingress
/// and egress maps, so neither is named for a role here.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct QosMapping { pub from: u32, pub to: u32 }

/// The kind-specific attributes, after their lengths are known good.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct VlanAttrs<'a> {
    pub id: Option<u16>,
    pub flags: Option<FlagsRequest>,
    pub protocol: Option<u16>,
    pub ingress_qos: Option<&'a [u8]>,
    pub egress_qos: Option<&'a [u8]>,
}

/// The generic link attributes this kind reads.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct LinkAttrs<'a> {
    pub address: Option<&'a [u8]>,
    pub mtu: Option<u32>,
    pub link: Option<u32>,
}

/// Pick this kind's three inputs out of a link message's attribute blob. The
/// address keeps whatever width it arrived with — judging that is validation's
/// job, and the width itself is the thing being judged.
/// # C: O(N)
pub fn parse_link_attrs(blob: &[u8]) -> Result<LinkAttrs<'_>, Errno> {
    let mut out = LinkAttrs::default();
    nla::for_each(blob, |a| {
        match a.ty {
            IFLA_ADDRESS if out.address.is_none() => out.address = Some(a.payload),
            IFLA_MTU if out.mtu.is_none() => out.mtu = Some(a.u32()?),
            IFLA_LINK if out.link.is_none() => out.link = Some(a.u32()?),
            _ => {}
        }
        Ok(())
    })?;
    Ok(out)
}

/// Read the kind-specific blob. Only lengths are judged here; a value that is
/// the wrong width for its attribute is out of range.
/// # C: O(N)
pub fn parse(blob: &[u8]) -> Result<VlanAttrs<'_>, Errno> {
    let mut out = VlanAttrs::default();
    nla::for_each(blob, |a| {
        match a.ty {
            IFLA_VLAN_ID if out.id.is_none() => {
                let _ = a.min_len(NLA_U16_LEN)?;
                out.id = Some(a.u16()?);
            }
            IFLA_VLAN_PROTOCOL if out.protocol.is_none() => {
                let _ = a.min_len(NLA_U16_LEN)?;
                out.protocol = Some(a.be16()?);
            }
            IFLA_VLAN_FLAGS if out.flags.is_none() => {
                let p = a.min_len(IFLA_VLAN_FLAGS_LEN)?;
                out.flags = Some(FlagsRequest {
                    flags: u32::from_ne_bytes([p[0], p[1], p[2], p[3]]),
                    mask: u32::from_ne_bytes([p[4], p[5], p[6], p[7]]),
                });
            }
            IFLA_VLAN_INGRESS_QOS if out.ingress_qos.is_none() => {
                out.ingress_qos = Some(nested(a.payload)?);
            }
            IFLA_VLAN_EGRESS_QOS if out.egress_qos.is_none() => {
                out.egress_qos = Some(nested(a.payload)?);
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(out)
}

/// A container is either empty or large enough to hold one attribute header.
/// # C: O(1)
fn nested(payload: &[u8]) -> Result<&[u8], Errno> {
    if !payload.is_empty() && payload.len() < NLA_HDR_LEN { return Err(Errno::Erange); }
    Ok(payload)
}

/// The translations inside one map container. Attributes that are not
/// translations are ignored; a translation too short to hold both ends is out
/// of range. # C: O(N)
pub fn qos_mappings(blob: &[u8]) -> Result<Vec<QosMapping>, Errno> {
    let mut out = Vec::new();
    nla::for_each(blob, |a| {
        if a.ty != IFLA_VLAN_QOS_MAPPING { return Ok(()); }
        let p = a.min_len(IFLA_VLAN_QOS_MAPPING_LEN)?;
        out.push(QosMapping {
            from: u32::from_ne_bytes([p[0], p[1], p[2], p[3]]),
            to: u32::from_ne_bytes([p[4], p[5], p[6], p[7]]),
        });
        Ok(())
    })?;
    Ok(out)
}

/// Whether an address can be an interface's own: a real, individual station
/// address. # C: O(1)
pub fn valid_ether_addr(addr: &[u8]) -> bool {
    addr.len() == ETH_ALEN && addr[0] & 0x01 == 0 && addr.iter().any(|b| *b != 0)
}

/// Judge a request without touching any interface.
///
/// Order matters and is observable: a caller sending several bad attributes at
/// once is told about them in this sequence.
/// # C: O(N)
pub fn validate(link: &LinkAttrs, data: Option<&VlanAttrs>) -> Result<(), Errno> {
    if let Some(addr) = link.address {
        if addr.len() != ETH_ALEN { return Err(Errno::Einval); }
        if !valid_ether_addr(addr) { return Err(Errno::Eaddrnotavail); }
    }
    let Some(data) = data else { return Err(Errno::Einval) };
    if let Some(proto) = data.protocol {
        if proto != ETH_P_8021Q && proto != ETH_P_8021AD {
            return Err(Errno::Eprotonosupport);
        }
    }
    if let Some(id) = data.id {
        if id >= VLAN_VID_MASK { return Err(Errno::Erange); }
    }
    if let Some(f) = data.flags {
        if !known(f.flags & f.mask) { return Err(Errno::Einval); }
    }
    if let Some(blob) = data.ingress_qos { qos_mappings(blob)?; }
    if let Some(blob) = data.egress_qos { qos_mappings(blob)?; }
    Ok(())
}

/// Everything needed to build the interface, with every refusal already made.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateRequest {
    pub real: NetIfaceId,
    pub caps: RealDevCaps,
    pub vlan_id: u16,
    pub proto: u16,
    pub mtu: u32,
    pub mac: MacAddr,
    pub flags: u32,
    pub ingress: Vec<QosMapping>,
    pub egress: Vec<QosMapping>,
}

/// Turn a validated request into a creation, refusing what the lower interface
/// or an existing interface makes impossible.
///
/// `resolve` maps the requested lower interface index to a live interface;
/// `table` is consulted for a tag that is already claimed.
/// # C: O(N)
pub fn newlink(link: &LinkAttrs, data: &VlanAttrs, table: &VlanTable,
               resolve: impl FnOnce(u32) -> Option<(NetIfaceId, RealDevCaps)>)
    -> Result<CreateRequest, Errno>
{
    let Some(vlan_id) = data.id else { return Err(Errno::Einval) };
    let Some(ifindex) = link.link else { return Err(Errno::Einval) };
    let Some((real, caps)) = resolve(ifindex) else { return Err(Errno::Enodev) };
    let proto = data.protocol.unwrap_or(ETH_P_8021Q);

    check_real_dev(&caps)?;
    if table.contains(&VlanKey::new(real, proto, vlan_id)) { return Err(Errno::Eexist); }

    let ceiling = max_mtu(&caps);
    let mtu = match link.mtu {
        None => ceiling,
        Some(requested) if requested > ceiling => return Err(Errno::Einval),
        Some(requested) => requested,
    };

    let mut mac = MacAddr::ZERO;
    if let Some(addr) = link.address {
        if addr.len() == ETH_ALEN { mac.0.copy_from_slice(addr); }
    }

    Ok(CreateRequest {
        real, caps, vlan_id, proto, mtu, mac,
        flags: VLAN_FLAG_DEFAULT,
        ingress: data.ingress_qos.map(qos_mappings).transpose()?.unwrap_or_default(),
        egress: data.egress_qos.map(qos_mappings).transpose()?.unwrap_or_default(),
    })
}

/// Apply a change request to a live interface.
///
/// The two maps take their ends in opposite orders: an ingress translation
/// names the code point first and the priority second, an egress translation
/// names the priority first and the code point second.
/// # C: O(N)
pub fn changelink(dev: &VlanDev, data: &VlanAttrs) -> Result<(), Errno> {
    if let Some(f) = data.flags { dev.change_flags(f.flags, f.mask)?; }
    if let Some(blob) = data.ingress_qos {
        let maps = qos_mappings(blob)?;
        dev.with_maps(|m| for e in &maps { m.set_ingress(e.to, e.from); });
    }
    if let Some(blob) = data.egress_qos {
        let maps = qos_mappings(blob)?;
        dev.with_maps(|m| for e in &maps { m.set_egress(e.from, e.to); });
    }
    Ok(())
}
