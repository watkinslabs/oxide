use alloc::vec::Vec;

use net::send_control::SendControl;
use crate::{Error, KResult};

const CMSG_HDR_LEN: usize = 16;
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
fn u64_at(bytes: &[u8], at: usize) -> u64 { u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap()) }

/// Parse native LP64 IP controls into one immutable transmit override. # C: O(control)
pub fn parse_raw_control(control: &[u8], ipv6: bool, cap_net_raw: bool, net_ns: u64)
    -> KResult<SendControl>
{
    let mut out = SendControl::default();
    let mut off = 0usize;
    while control.len().saturating_sub(off) >= CMSG_HDR_LEN {
        let len = usize::try_from(u64_at(control, off)).map_err(|_| Error::Einval)?;
        if len < CMSG_HDR_LEN || len > control.len() - off { return Err(Error::Einval); }
        let level = i32_at(control, off + 8);
        let kind = i32_at(control, off + 12);
        let data = &control[off + CMSG_HDR_LEN..off + len];
        if ipv6 && level == SOL_IPV6 { parse_v6(kind, data, cap_net_raw, &mut out)?; }
        else if !ipv6 && level == SOL_IP { parse_v4(kind, data, cap_net_raw, net_ns, &mut out)?; }
        let aligned = len.checked_add(7).ok_or_else(|| Error::Einval)? & !7;
        let next = off.checked_add(aligned).ok_or_else(|| Error::Einval)?;
        if next > control.len() { break; }
        off = next;
    }
    Ok(out)
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
