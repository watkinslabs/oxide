use alloc::vec::Vec;

use net::send_control::SendControl;
use crate::cmsg_walk::{CmsgWalk, SOL_SOCKET};
use crate::sockcm::SockCmEnv;
use crate::{Error, KResult};

const SOL_IP: i32 = 0;
const SOL_IPV6: i32 = 41;
const IP_TOS: i32 = 1;
const IP_TTL: i32 = 2;
const IP_RETOPTS: i32 = 7;
const IP_PKTINFO: i32 = 8;
const IP_PROTOCOL: i32 = 52;
const IPV6_2292PKTINFO: i32 = 2;
const IPV6_2292HOPOPTS: i32 = 3;
const IPV6_2292DSTOPTS: i32 = 4;
const IPV6_2292RTHDR: i32 = 5;
const IPV6_2292HOPLIMIT: i32 = 8;
const IPV6_FLOWINFO: i32 = 11;
const IPV6_PKTINFO: i32 = 50;
const IPV6_HOPLIMIT: i32 = 52;
const IPV6_HOPOPTS: i32 = 54;
const IPV6_RTHDRDSTOPTS: i32 = 55;
const IPV6_RTHDR: i32 = 57;
const IPV6_DSTOPTS: i32 = 59;
const IPV6_DONTFRAG: i32 = 62;
const IPV6_TCLASS: i32 = 67;
const IPV4_OPTION_MAX: usize = 40;

fn i32_at(bytes: &[u8], at: usize) -> i32 { i32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap()) }

/// One IP-level send-ancillary admission, snapshotted per message.
///
/// `allow_v6_pktinfo` is the AF_INET6 socket that fell back to the IPv4 send
/// path for a v4-mapped destination: it, and only it, accepts an `IPV6_PKTINFO`
/// carrying a v4-mapped source at the IPv4 level.
pub(crate) struct IpControlEnv {
    pub ipv6: bool,
    pub allow_v6_pktinfo: bool,
    pub cap_net_raw: bool,
    pub net_ns: u64,
    pub sockcm: SockCmEnv,
}

/// Parse native LP64 IP controls into one immutable transmit override.
///
/// This is the whole admission for every socket that speaks an IP transport —
/// UDP, ICMP datagram, and raw alike. Levels the transport does not own are
/// stepped over; its own level answers an unknown type with EINVAL; and
/// SOL_SOCKET is handed to the one generic rule rather than re-answered here.
/// # C: O(control)
pub(crate) fn parse_ip_control(control: &[u8], env: &IpControlEnv) -> KResult<SendControl> {
    let mut out = SendControl::default();
    for item in CmsgWalk::new(control) {
        let item = item?;
        if !env.ipv6 && env.allow_v6_pktinfo && item.level == SOL_IPV6
            && item.kind == IPV6_PKTINFO
        {
            parse_v4_mapped_pktinfo(item.data, &mut out)?;
            continue;
        }
        if item.level == SOL_SOCKET { crate::sockcm::admit(&env.sockcm, &item)?; continue; }
        if env.ipv6 && item.level == SOL_IPV6 {
            parse_v6(item.kind, item.data, env.cap_net_raw, &mut out)?;
        } else if !env.ipv6 && item.level == SOL_IP {
            parse_v4(item.kind, item.data, env.cap_net_raw, env.net_ns, &mut out)?;
        }
    }
    Ok(out)
}

/// The v4-mapped `IPV6_PKTINFO` an AF_INET6 socket may carry into the IPv4
/// send path: the interface selects the egress, and the low four bytes of the
/// mapped address select the source. A source that is not v4-mapped is EINVAL.
/// # C: O(1)
fn parse_v4_mapped_pktinfo(data: &[u8], out: &mut SendControl) -> KResult<()> {
    if data.len() < 20 { return Err(Error::Einval); }
    if data[..10].iter().any(|byte| *byte != 0) || data[10] != 0xff || data[11] != 0xff {
        return Err(Error::Einval);
    }
    let index = i32_at(data, 16);
    if index != 0 { out.raw4.iface = Some(net::NetIfaceId::from_raw(index as u32)); }
    let source = net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    if !source.is_unspecified() { out.raw4.source = Some(source); }
    Ok(())
}
fn parse_v4(kind: i32, data: &[u8], cap: bool, net_ns: u64, out: &mut SendControl)
    -> KResult<()>
{
    match kind {
        IP_PKTINFO => {
            if data.len() != 12 { return Err(Error::Einval); }
            let index = i32_at(data, 0);
            if index != 0 { out.raw4.iface = Some(net::NetIfaceId::from_raw(index as u32)); }
            let source = net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            if !source.is_unspecified() { out.raw4.source = Some(source); }
        }
        IP_TTL => out.raw4.ttl = Some(parse_u8_int(data, 1)?),
        IP_TOS => {
            out.raw4.tos = Some(if data.len() == 1 { data[0] }
                else { parse_u8_int(data, 0)? });
        }
        IP_PROTOCOL => out.raw4.protocol = Some(parse_u8_int(data, 1)?),
        IP_RETOPTS => {
            out.raw4.options =
                Some(parse_ip_options(&data[..data.len().min(IPV4_OPTION_MAX)], cap, net_ns)?);
        }
        _ => return Err(Error::Einval),
    }
    Ok(())
}

fn parse_v6(kind: i32, data: &[u8], cap: bool, out: &mut SendControl) -> KResult<()> {
    match kind {
        IPV6_PKTINFO | IPV6_2292PKTINFO => {
            if data.len() < 20 { return Err(Error::Einval); }
            let mut addr = [0u8; 16]; addr.copy_from_slice(&data[..16]);
            let source = net::Ipv6Addr(addr);
            if !source.is_unspecified() { out.raw6.source = Some(source); }
            let index = i32_at(data, 16);
            if index != 0 { out.raw6.iface = Some(net::NetIfaceId::from_raw(index as u32)); }
        }
        IPV6_HOPLIMIT | IPV6_2292HOPLIMIT => out.raw6.hop_limit = Some(parse_i32_range(data, -1, 255)?),
        IPV6_TCLASS => out.raw6.traffic_class = Some(parse_i32_range(data, -1, 255)?),
        IPV6_FLOWINFO => {
            if data.len() < 4 { return Err(Error::Einval); }
            out.raw6.flowinfo = Some(u32::from_be_bytes(data[..4].try_into().unwrap()) & 0x0fff_ffff);
        }
        IPV6_DONTFRAG => out.raw6.dontfrag = Some(match parse_i32_range(data, 0, 1)? { 0 => false, _ => true }),
        IPV6_HOPOPTS | IPV6_2292HOPOPTS => {
            if out.raw6.hop_options.is_some() { return Err(Error::Einval); }
            out.raw6.hop_options = Some(parse_ext(data, cap)?);
        }
        IPV6_RTHDRDSTOPTS => out.raw6.dst_before_routing = Some(parse_ext(data, cap)?),
        IPV6_DSTOPTS => out.raw6.dst_after_routing = Some(parse_ext(data, cap)?),
        IPV6_2292DSTOPTS => {
            if out.raw6.dst_after_routing.is_some() { return Err(Error::Einval); }
            out.raw6.dst_after_routing = Some(parse_ext(data, cap)?);
        }
        IPV6_RTHDR | IPV6_2292RTHDR => {
            let routing = parse_routing(data)?;
            out.raw6.routing = Some(routing);
            if kind == IPV6_2292RTHDR && out.raw6.dst_after_routing.is_some() {
                out.raw6.dst_before_routing = out.raw6.dst_after_routing.take();
            }
        }
        _ => return Err(Error::Einval),
    }
    Ok(())
}

fn parse_u8_int(data: &[u8], min: i32) -> KResult<u8> {
    Ok(parse_i32_range(data, min, 255)? as u8)
}

fn parse_i32_range(data: &[u8], min: i32, max: i32) -> KResult<i32> {
    if data.len() != 4 { return Err(Error::Einval); }
    let value = i32_at(data, 0);
    if value < min || value > max { return Err(Error::Einval); }
    Ok(value)
}

fn parse_ext(data: &[u8], cap: bool) -> KResult<Vec<u8>> {
    if data.len() < 2 { return Err(Error::Einval); }
    let len = (data[1] as usize + 1) * 8;
    if data.len() < len { return Err(Error::Einval); }
    if !cap { return Err(Error::Eperm); }
    Ok(data[..len].to_vec())
}

fn parse_routing(data: &[u8]) -> KResult<Vec<u8>> {
    if data.len() < 4 { return Err(Error::Einval); }
    let len = (data[1] as usize + 1) * 8;
    if data.len() < len || data[2] != 2 || data[1] != 2 || data[3] != 1 {
        return Err(Error::Einval);
    }
    Ok(data[..len].to_vec())
}

/// The `IP_OPTIONS` control message enters the same compile pass the
/// socket-level option does, so one message and one `setsockopt` produce the
/// identical compiled area. # C: O(optlen)
fn parse_ip_options(data: &[u8], cap: bool, net_ns: u64)
    -> KResult<net::ipv4_options::Compiled>
{
    net::ipv4_options::build_control(data, cap, net_ns).map_err(Error::from)
}
