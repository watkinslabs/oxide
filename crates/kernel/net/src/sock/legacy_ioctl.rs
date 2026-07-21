use crate::{NetError, socket_args::AF_INET_SOCK_WIRE, uapi::SIOCRTMSG};

/// Return the IPv4 protocol owner's terminal result for a legacy socket ioctl. # C: O(1)
pub fn legacy_ioctl_errno(family: u16, request: u64) -> Option<NetError> {
    match (family, request) {
        (AF_INET_SOCK_WIRE, SIOCRTMSG) => Some(NetError::Einval),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket_args::{AF_INET6_SOCK_WIRE, AF_UNIX_SOCK_WIRE};

    #[test]
    fn ipv4_rtmsg_stops_before_generic_ifreq_import() {
        assert_eq!(legacy_ioctl_errno(AF_INET_SOCK_WIRE, SIOCRTMSG), Some(NetError::Einval));
        assert_eq!(legacy_ioctl_errno(AF_UNIX_SOCK_WIRE, SIOCRTMSG), None);
        assert_eq!(legacy_ioctl_errno(AF_INET6_SOCK_WIRE, SIOCRTMSG), None);
    }
}
