// Terminal legacy netdevice ioctl ABI shim — exact generic-Linux outcomes.

use syscall::errno::Errno;

/// Apply a legacy device ioctl with no modeled device-specific owner. # C: O(N interfaces)
pub(super) fn handle(net_ns: u64, request: u64, arg: u64) -> i64 {
    let ifreq = match super::read_ifreq(arg) {
        Some(ifreq) => ifreq, None => return -(Errno::Efault.as_i32() as i64),
    };
    match request {
        super::SIOCGIFSLAVE | super::SIOCSIFSLAVE => {
            let name = match super::copied_ifname(&ifreq) {
                Some(name) => name, None => return -(Errno::Efault.as_i32() as i64),
            };
            if net::sock::stack().ifaces.lookup_name_in_ns(name, net_ns).is_none() {
                return -(Errno::Enodev.as_i32() as i64);
            }
            -(Errno::Einval.as_i32() as i64)
        }
        super::SIOCSIFLINK | super::SIOCGIFMEM | super::SIOCSIFMEM
        | super::SIOCGIFENCAP | super::SIOCSIFENCAP => -(Errno::Enotty.as_i32() as i64),
        _ => -(Errno::Enotty.as_i32() as i64),
    }
}
