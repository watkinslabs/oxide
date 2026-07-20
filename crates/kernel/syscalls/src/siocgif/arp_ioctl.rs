// SIOC*ARP syscall ABI shim — usercopy then canonical net neighbour owner.

use syscall::errno::Errno;

use super::user_range;

/// Copy one fixed-layout Linux `arpreq`, invoke its network owner, and copy a getter reply. # C: O(N routes + log N neighbours)
pub(super) fn handle(net_ns: u64, request: u64, arg: u64) -> i64 {
    if !user_range(arg, net::arp::uapi::ARPREQ_SIZE) {
        return -(Errno::Efault.as_i32() as i64);
    }
    let mut arpreq = [0u8; net::arp::uapi::ARPREQ_SIZE];
    if uaccess::copy_from_user(&mut arpreq, arg).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    if let Err(error) = net::arp::ioctl(net::sock::stack(), net_ns, request, &mut arpreq) {
        return -(error.as_i32() as i64);
    }
    if request == net::arp::uapi::SIOCGARP
        && uaccess::copy_to_user(arg, &arpreq).is_err()
    {
        return -(Errno::Efault.as_i32() as i64);
    }
    0
}
