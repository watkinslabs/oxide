// SIOCETHTOOL ABI shim — parse ifreq + the pointed-to ethtool command block,
// then answer from the netdev owner's live interface flags.
//
// Only ETHTOOL_GLINK is answered. Linux returns EOPNOTSUPP for any command a
// driver does not implement, so an unimplemented command is a Linux-correct
// answer here rather than a stub: ethtool(8) and NetworkManager both probe
// GLINK for carrier and fall back cleanly on EOPNOTSUPP for the rest.
//
// Carrier is `IFF_RUNNING` per `net::netdev::iff` — the same bit
// `SIOCGIFFLAGS` reports — so GLINK and the flags ioctl can never disagree.

use syscall::errno::Errno;

pub(super) const SIOCETHTOOL: u64 = 0x8946;

/// `ethtool_value` command selector (`ETHTOOL_GLINK`) per Linux
/// `include/uapi/linux/ethtool.h`.
const ETHTOOL_GLINK: u32 = 0x0000_000a;
/// `struct ethtool_value` = `{ __u32 cmd; __u32 data; }`.
const ETHTOOL_VALUE_LEN: usize = 8;
/// Byte offset of `ifr_data` inside `ifreq` (the union follows `ifr_name`).
const IFREQ_DATA_OFFSET: usize = super::IFNAMSIZ;

/// Answer one bounded `SIOCETHTOOL` command. # C: O(N interfaces)
pub(super) fn handle(net_ns: u64, arg: u64) -> i64 {
    let Some(ifreq) = super::read_ifreq(arg) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(name) = super::copied_ifname(&ifreq) else { return -(Errno::Efault.as_i32() as i64); };
    let data = u64::from_ne_bytes([
        ifreq[IFREQ_DATA_OFFSET], ifreq[IFREQ_DATA_OFFSET + 1],
        ifreq[IFREQ_DATA_OFFSET + 2], ifreq[IFREQ_DATA_OFFSET + 3],
        ifreq[IFREQ_DATA_OFFSET + 4], ifreq[IFREQ_DATA_OFFSET + 5],
        ifreq[IFREQ_DATA_OFFSET + 6], ifreq[IFREQ_DATA_OFFSET + 7],
    ]);
    let mut value = [0u8; ETHTOOL_VALUE_LEN];
    if uaccess::copy_from_user(&mut value, data).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    if u32::from_ne_bytes([value[0], value[1], value[2], value[3]]) != ETHTOOL_GLINK {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    let Some((id, _)) = net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) else {
        return -(Errno::Enodev.as_i32() as i64);
    };
    let flags = match super::live_iface_flags(id) {
        Ok(flags) => flags,
        Err(errno) => return -(errno.as_i32() as i64),
    };
    // `live_iface_flags` reports the 16-bit ifreq flag word; IFF_RUNNING (0x40)
    // fits it, so widen for the comparison rather than truncating the constant.
    let carrier = (flags as u32 & net::netdev::iff::IFF_RUNNING != 0) as u32;
    value[4..ETHTOOL_VALUE_LEN].copy_from_slice(&carrier.to_ne_bytes());
    if uaccess::copy_to_user(data, &value).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    0
}
