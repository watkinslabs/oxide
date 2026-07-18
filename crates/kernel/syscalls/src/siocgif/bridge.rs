//! Legacy Linux bridge ioctl ABI: raw BRCTL vectors and `SIOCDEVPRIVATE`.

use super::{copied_ifname, read_ifreq, user_range, SiocAccess, IFNAMSIZ};
use syscall::errno::Errno;

const SIOCBRADDBR: u64 = 0x89a0;
const SIOCBRDELBR: u64 = 0x89a1;
const SIOCBRADDIF: u64 = 0x89a2;
const SIOCBRDELIF: u64 = 0x89a3;
const SIOCGIFBR: u64 = 0x8940;
const SIOCSIFBR: u64 = 0x8941;
const SIOCDEVPRIVATE: u64 = 0x89f0;
const BRCTL_GET_VERSION: u64 = 0;
const BRCTL_GET_BRIDGES: u64 = 1;
const BRCTL_ADD_BRIDGE: u64 = 2;
const BRCTL_DEL_BRIDGE: u64 = 3;
const BRCTL_GET_BRIDGE_INFO: u64 = 6;
const BRCTL_GET_PORT_LIST: u64 = 7;
const BRCTL_ADD_IF: u64 = 4;
const BRCTL_DEL_IF: u64 = 5;
const BRCTL_SET_BRIDGE_FORWARD_DELAY: u64 = 8;
const BRCTL_SET_BRIDGE_HELLO_TIME: u64 = 9;
const BRCTL_SET_BRIDGE_MAX_AGE: u64 = 10;
const BRCTL_SET_AGEING_TIME: u64 = 11;
const BRCTL_SET_GC_INTERVAL: u64 = 12;
const BRCTL_SET_BRIDGE_STP_STATE: u64 = 14;
const BRCTL_SET_BRIDGE_PRIORITY: u64 = 15;
const BRCTL_SET_PORT_PRIORITY: u64 = 16;
const BRCTL_SET_PATH_COST: u64 = 17;
const BRCTL_GET_FDB_ENTRIES: u64 = 18;
const BR_MAX_PORTS: usize = 1024;
const BRCTL_FDB_ENTRY_SIZE: usize = 16;
const BRCTL_FDB_MAX_ENTRIES: usize = hal::PAGE_SIZE_BYTES as usize / BRCTL_FDB_ENTRY_SIZE;
const BRCTL_FDB_PORT_LO_OFFSET: usize = 6;
const BRCTL_FDB_LOCAL_OFFSET: usize = 7;
const BRCTL_FDB_AGEING_OFFSET: usize = 8;
const BRCTL_FDB_PORT_HI_OFFSET: usize = 12;
const BRCTL_BRIDGE_INFO_SIZE: usize = 72;
const BRCTL_INFO_ROOT_OFFSET: usize = 0;
const BRCTL_INFO_BRIDGE_ID_OFFSET: usize = 8;
const BRCTL_INFO_ROOT_PATH_COST_OFFSET: usize = 16;
const BRCTL_INFO_MAX_AGE_OFFSET: usize = 20;
const BRCTL_INFO_HELLO_TIME_OFFSET: usize = 24;
const BRCTL_INFO_FORWARD_DELAY_OFFSET: usize = 28;
const BRCTL_INFO_BRIDGE_MAX_AGE_OFFSET: usize = 32;
const BRCTL_INFO_BRIDGE_HELLO_TIME_OFFSET: usize = 36;
const BRCTL_INFO_BRIDGE_FORWARD_DELAY_OFFSET: usize = 40;
const BRCTL_INFO_TOPOLOGY_CHANGE_OFFSET: usize = 44;
const BRCTL_INFO_TOPOLOGY_CHANGE_DETECTED_OFFSET: usize = 45;
const BRCTL_INFO_ROOT_PORT_OFFSET: usize = 46;
const BRCTL_INFO_STP_ENABLED_OFFSET: usize = 47;
const BRCTL_INFO_AGEING_TIME_OFFSET: usize = 48;
const BRCTL_INFO_GC_INTERVAL_OFFSET: usize = 52;
const BRCTL_INFO_GC_INTERVAL_END: usize = 56;

pub(super) fn access(req: u64, arg: u64) -> Result<Option<SiocAccess>, i64> {
    match req {
        SIOCGIFBR => Ok(Some(SiocAccess::Get)),
        SIOCDEVPRIVATE => private_access(arg).map(Some),
        SIOCBRADDBR | SIOCBRDELBR | SIOCBRADDIF | SIOCBRDELIF | SIOCSIFBR => Ok(Some(SiocAccess::Mutate)),
        _ => Ok(None),
    }
}

pub(super) fn arg_size(req: u64) -> Option<usize> {
    match req {
        SIOCBRADDBR | SIOCBRDELBR => Some(IFNAMSIZ),
        SIOCGIFBR | SIOCSIFBR => Some(3 * core::mem::size_of::<u64>()),
        SIOCBRADDIF | SIOCBRDELIF | SIOCDEVPRIVATE => Some(super::IFREQ_SIZE),
        _ => None,
    }
}

pub(super) fn handle(net_ns: u64, req: u64, arg: u64) -> Option<i64> {
    Some(match req {
        SIOCBRADDBR => add_bridge(net_ns, arg), SIOCBRDELBR => del_bridge(net_ns, arg),
        SIOCBRADDIF => add_del_if(net_ns, arg, true), SIOCBRDELIF => add_del_if(net_ns, arg, false),
        SIOCGIFBR => vector(net_ns, arg, false), SIOCSIFBR => vector(net_ns, arg, true),
        SIOCDEVPRIVATE => private(net_ns, arg), _ => return None,
    })
}

fn bridge_name(arg: u64) -> Result<alloc::string::String, i64> {
    let mut bytes = [0u8; IFNAMSIZ];
    if uaccess::copy_from_user(&mut bytes, arg).is_err() { return Err(-(Errno::Efault.as_i32() as i64)); }
    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(IFNAMSIZ);
    if end == 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    core::str::from_utf8(&bytes[..end]).map(alloc::string::ToString::to_string)
        .map_err(|_| -(Errno::Einval.as_i32() as i64))
}

fn errno(error: net::NetError) -> i64 { crate::net_common::errno_from_neterr(error) }

fn add_bridge(net_ns: u64, arg: u64) -> i64 {
    let name = match bridge_name(arg) { Ok(name) => name, Err(rv) => return rv };
    net::sock::stack().bridge_create_named(net_ns, &name).map(|_| 0).unwrap_or_else(errno)
}

fn del_bridge(net_ns: u64, arg: u64) -> i64 {
    let name = match bridge_name(arg) { Ok(name) => name, Err(rv) => return rv };
    net::sock::stack().bridge_delete_named(net_ns, &name).map(|()| 0).unwrap_or_else(errno)
}

fn add_del_if(net_ns: u64, arg: u64, add: bool) -> i64 {
    let req = match read_ifreq(arg) { Some(req) => req, None => return -(Errno::Efault.as_i32() as i64) };
    let name = match copied_ifname(&req) { Some(name) if !name.is_empty() => name, _ => return -(Errno::Einval.as_i32() as i64) };
    let index = i32::from_ne_bytes([req[16], req[17], req[18], req[19]]);
    if index <= 0 { return -(Errno::Enodev.as_i32() as i64); }
    let port = net::NetIfaceId::from_raw(index as u32);
    let stack = net::sock::stack();
    let result = if add { stack.bridge_add_port_ifindex(net_ns, name, port) }
        else { stack.bridge_del_port_ifindex(net_ns, name, port) };
    result.map(|()| 0).unwrap_or_else(errno)
}

fn words3(arg: u64) -> Result<[u64; 3], i64> {
    if !user_range(arg, 3 * core::mem::size_of::<u64>()) { return Err(-(Errno::Efault.as_i32() as i64)); }
    let mut raw = [0u8; 24];
    if uaccess::copy_from_user(&mut raw, arg).is_err() { return Err(-(Errno::Efault.as_i32() as i64)); }
    Ok([u64::from_ne_bytes(raw[0..8].try_into().unwrap()),
        u64::from_ne_bytes(raw[8..16].try_into().unwrap()),
        u64::from_ne_bytes(raw[16..24].try_into().unwrap())])
}

fn words4(arg: u64) -> Result<[u64; 4], i64> {
    if !user_range(arg, 4 * core::mem::size_of::<u64>()) { return Err(-(Errno::Efault.as_i32() as i64)); }
    let mut raw = [0u8; 32];
    if uaccess::copy_from_user(&mut raw, arg).is_err() { return Err(-(Errno::Efault.as_i32() as i64)); }
    Ok([u64::from_ne_bytes(raw[0..8].try_into().unwrap()),
        u64::from_ne_bytes(raw[8..16].try_into().unwrap()),
        u64::from_ne_bytes(raw[16..24].try_into().unwrap()),
        u64::from_ne_bytes(raw[24..32].try_into().unwrap())])
}

fn private_access(arg: u64) -> Result<SiocAccess, i64> {
    let req = read_ifreq(arg).ok_or(-(Errno::Efault.as_i32() as i64))?;
    let data = u64::from_ne_bytes(req[16..24].try_into().unwrap());
    let args = words4(data)?;
    match args[0] {
        BRCTL_ADD_IF | BRCTL_DEL_IF
        | BRCTL_SET_BRIDGE_FORWARD_DELAY | BRCTL_SET_BRIDGE_HELLO_TIME
        | BRCTL_SET_BRIDGE_MAX_AGE | BRCTL_SET_AGEING_TIME | BRCTL_SET_GC_INTERVAL
        | BRCTL_SET_BRIDGE_STP_STATE | BRCTL_SET_BRIDGE_PRIORITY
        | BRCTL_SET_PORT_PRIORITY | BRCTL_SET_PATH_COST => Ok(SiocAccess::Mutate),
        _ => Ok(SiocAccess::Get),
    }
}

fn vector(net_ns: u64, arg: u64, mutate: bool) -> i64 {
    let args = match words3(arg) { Ok(args) => args, Err(rv) => return rv };
    match args[0] {
        BRCTL_GET_VERSION if !mutate => 1,
        BRCTL_GET_BRIDGES if !mutate => {
            if args[2] >= 2048 { return -(Errno::Enomem.as_i32() as i64); }
            let ids = net::sock::stack().bridge_ifindices(net_ns);
            let count = core::cmp::min(ids.len(), args[2] as usize);
            let mut bytes = alloc::vec![0u8; count * 4];
            for (slot, iface) in bytes.chunks_exact_mut(4).zip(ids) { slot.copy_from_slice(&(iface.raw() as i32).to_ne_bytes()); }
            if uaccess::copy_to_user(args[1], &bytes).is_err() { -(Errno::Efault.as_i32() as i64) } else { count as i64 }
        }
        BRCTL_ADD_BRIDGE if mutate => add_bridge(net_ns, args[1]),
        BRCTL_DEL_BRIDGE if mutate => del_bridge(net_ns, args[1]),
        _ => -(Errno::Eopnotsupp.as_i32() as i64),
    }
}

fn private(net_ns: u64, arg: u64) -> i64 {
    let req = match read_ifreq(arg) { Some(req) => req, None => return -(Errno::Efault.as_i32() as i64) };
    let name = match copied_ifname(&req) { Some(name) if !name.is_empty() => name, _ => return -(Errno::Einval.as_i32() as i64) };
    let data = u64::from_ne_bytes(req[16..24].try_into().unwrap());
    let args = match words4(data) { Ok(args) => args, Err(rv) => return rv };
    let (bridge, _) = match net::sock::stack().ifaces.lookup_name_in_ns(name, net_ns) {
        Some(found) => found, None => return -(Errno::Enodev.as_i32() as i64),
    };
    match args[0] {
        BRCTL_ADD_IF => private_add_del_if(net_ns, name, args[1], true),
        BRCTL_DEL_IF => private_add_del_if(net_ns, name, args[1], false),
        BRCTL_SET_AGEING_TIME => net::sock::stack().bridge_set_ageing_time(net_ns, bridge, args[1])
            .map(|()| 0).unwrap_or_else(errno),
        BRCTL_GET_BRIDGE_INFO => bridge_info(net_ns, bridge, args[1]),
        BRCTL_GET_PORT_LIST => port_list(net_ns, bridge, args),
        BRCTL_GET_FDB_ENTRIES => fdb_entries(net_ns, bridge, args),
        _ => -(Errno::Eopnotsupp.as_i32() as i64),
    }
}

fn bridge_info(net_ns: u64, bridge: net::NetIfaceId, output: u64) -> i64 {
    let info = match net::sock::stack().bridge_info(net_ns, bridge) {
        Ok(info) => info, Err(net::NetError::Enodev) => return -(Errno::Eopnotsupp.as_i32() as i64), Err(error) => return errno(error),
    };
    let mut bytes = [0u8; BRCTL_BRIDGE_INFO_SIZE];
    bytes[BRCTL_INFO_ROOT_OFFSET..BRCTL_INFO_BRIDGE_ID_OFFSET].copy_from_slice(&info.designated_root);
    bytes[BRCTL_INFO_BRIDGE_ID_OFFSET..BRCTL_INFO_ROOT_PATH_COST_OFFSET].copy_from_slice(&info.bridge_id);
    bytes[BRCTL_INFO_ROOT_PATH_COST_OFFSET..BRCTL_INFO_MAX_AGE_OFFSET].copy_from_slice(&info.root_path_cost.to_ne_bytes());
    bytes[BRCTL_INFO_MAX_AGE_OFFSET..BRCTL_INFO_HELLO_TIME_OFFSET].copy_from_slice(&info.max_age.to_ne_bytes());
    bytes[BRCTL_INFO_HELLO_TIME_OFFSET..BRCTL_INFO_FORWARD_DELAY_OFFSET].copy_from_slice(&info.hello_time.to_ne_bytes());
    bytes[BRCTL_INFO_FORWARD_DELAY_OFFSET..BRCTL_INFO_BRIDGE_MAX_AGE_OFFSET].copy_from_slice(&info.forward_delay.to_ne_bytes());
    bytes[BRCTL_INFO_BRIDGE_MAX_AGE_OFFSET..BRCTL_INFO_BRIDGE_HELLO_TIME_OFFSET].copy_from_slice(&info.bridge_max_age.to_ne_bytes());
    bytes[BRCTL_INFO_BRIDGE_HELLO_TIME_OFFSET..BRCTL_INFO_BRIDGE_FORWARD_DELAY_OFFSET].copy_from_slice(&info.bridge_hello_time.to_ne_bytes());
    bytes[BRCTL_INFO_BRIDGE_FORWARD_DELAY_OFFSET..BRCTL_INFO_TOPOLOGY_CHANGE_OFFSET].copy_from_slice(&info.bridge_forward_delay.to_ne_bytes());
    bytes[BRCTL_INFO_TOPOLOGY_CHANGE_OFFSET] = info.topology_change;
    bytes[BRCTL_INFO_TOPOLOGY_CHANGE_DETECTED_OFFSET] = info.topology_change_detected;
    bytes[BRCTL_INFO_ROOT_PORT_OFFSET] = info.root_port;
    bytes[BRCTL_INFO_STP_ENABLED_OFFSET] = info.stp_enabled;
    bytes[BRCTL_INFO_AGEING_TIME_OFFSET..BRCTL_INFO_GC_INTERVAL_OFFSET].copy_from_slice(&info.ageing_time.to_ne_bytes());
    bytes[BRCTL_INFO_GC_INTERVAL_OFFSET..BRCTL_INFO_GC_INTERVAL_END].copy_from_slice(&info.gc_interval.to_ne_bytes());
    if uaccess::copy_to_user(output, &bytes).is_err() { -(Errno::Efault.as_i32() as i64) } else { 0 }
}

fn private_add_del_if(net_ns: u64, bridge: &str, ifindex: u64, add: bool) -> i64 {
    if ifindex > i32::MAX as u64 { return -(Errno::Einval.as_i32() as i64); }
    let port = net::NetIfaceId::from_raw(ifindex as u32);
    let stack = net::sock::stack();
    let result = if add { stack.bridge_add_port_ifindex(net_ns, bridge, port) }
        else { stack.bridge_del_port_ifindex(net_ns, bridge, port) };
    result.map(|()| 0).unwrap_or_else(errno)
}

fn port_list(net_ns: u64, bridge: net::NetIfaceId, args: [u64; 4]) -> i64 {
    let requested = args[2] as i64;
    if requested < 0 { return -(Errno::Einval.as_i32() as i64); }
    let count = if requested == 0 { 256 } else { core::cmp::min(requested as usize, BR_MAX_PORTS) };
    let rows = match net::sock::stack().bridge_port_list(net_ns, bridge, count) {
        Ok(rows) => rows, Err(net::NetError::Enodev) => return -(Errno::Eopnotsupp.as_i32() as i64), Err(error) => return errno(error),
    };
    let mut bytes = alloc::vec![0u8; rows.len() * core::mem::size_of::<i32>()];
    for (dst, row) in bytes.chunks_exact_mut(4).zip(rows) { dst.copy_from_slice(&row.to_ne_bytes()); }
    if uaccess::copy_to_user(args[1], &bytes).is_err() { -(Errno::Efault.as_i32() as i64) } else { count as i64 }
}

fn fdb_entries(net_ns: u64, bridge: net::NetIfaceId, args: [u64; 4]) -> i64 {
    if args[2] > i32::MAX as u64 || args[3] > i32::MAX as u64 { return -(Errno::Einval.as_i32() as i64); }
    let requested = args[2] as usize;
    let offset = args[3] as usize;
    let count = core::cmp::min(requested, BRCTL_FDB_MAX_ENTRIES);
    let rows = match net::sock::stack().bridge_fdb_entries(net_ns, bridge, offset, count) {
        Ok(rows) => rows, Err(net::NetError::Enodev) => return -(Errno::Eopnotsupp.as_i32() as i64), Err(error) => return errno(error),
    };
    let copied = rows.len();
    let mut bytes = alloc::vec![0u8; rows.len() * BRCTL_FDB_ENTRY_SIZE];
    for (dst, row) in bytes.chunks_exact_mut(BRCTL_FDB_ENTRY_SIZE).zip(rows) {
        dst[..6].copy_from_slice(&row.mac.0);
        dst[BRCTL_FDB_PORT_LO_OFFSET] = row.port_no as u8;
        dst[BRCTL_FDB_LOCAL_OFFSET] = u8::from(row.local);
        dst[BRCTL_FDB_AGEING_OFFSET..BRCTL_FDB_PORT_HI_OFFSET].copy_from_slice(&row.ageing_ticks.to_ne_bytes());
        dst[BRCTL_FDB_PORT_HI_OFFSET] = (row.port_no >> 8) as u8;
    }
    if bytes.is_empty() { return 0; }
    if uaccess::copy_to_user(args[1], &bytes).is_err() { -(Errno::Efault.as_i32() as i64) } else { copied as i64 }
}
