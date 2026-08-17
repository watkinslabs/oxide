// Which `NETLINK_*` protocols have a kernel end.
//
// `socket(AF_NETLINK, …, protocol)` answers `EPROTONOSUPPORT` for a protocol
// whose kernel socket was never created — netlink has no module autoload for a
// family nothing registered. The list is therefore the set of families this
// kernel actually implements, and adding a number to it without the family
// behind it hands userspace a socket that answers nothing.
//
// Ungated on purpose: the syscall slot that consumes this is
// `cfg(target_os = "oxide-kernel")`, so a test inside it would compile out and
// report nothing (`docs/53`).

use crate::wire::proto;

/// Whether this kernel registered a socket on `protocol`. # C: O(1)
pub fn protocol_registered(protocol: u32) -> bool {
    let Ok(p) = u16::try_from(protocol) else { return false; };
    matches!(p,
        proto::NETLINK_ROUTE
        | proto::NETLINK_USERSOCK
        | proto::NETLINK_SOCK_DIAG
        | proto::NETLINK_SELINUX
        | proto::NETLINK_AUDIT
        | proto::NETLINK_NETFILTER
        | proto::NETLINK_KOBJECT_UEVENT
        | proto::NETLINK_GENERIC
    )
}

/// Whether `protocol` is notification-only: its kernel end registers no
/// receive path, so nothing userspace sends is ever dispatched. A unicast to
/// such a kernel socket is refused with `ECONNREFUSED` rather than answered.
/// # C: O(1)
pub fn notification_only(protocol: u16) -> bool {
    matches!(protocol, proto::NETLINK_SELINUX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_selinux_family_is_registered() {
        // The reference creates this family whenever the label module is built
        // in, and both target arches select it: on Linux the socket always
        // opens. `libselinux`'s userspace AVC treats a refusal as fatal, and
        // `dbus-daemon` built against it then cannot start the session bus.
        assert!(protocol_registered(proto::NETLINK_SELINUX as u32));
        assert_eq!(proto::NETLINK_SELINUX, 7);
    }

    #[test]
    fn the_families_with_a_kernel_end_are_registered() {
        for p in [proto::NETLINK_ROUTE, proto::NETLINK_USERSOCK, proto::NETLINK_SOCK_DIAG,
                  proto::NETLINK_SELINUX, proto::NETLINK_AUDIT, proto::NETLINK_NETFILTER,
                  proto::NETLINK_KOBJECT_UEVENT, proto::NETLINK_GENERIC] {
            assert!(protocol_registered(p as u32), "protocol {p} must be registered");
        }
    }

    #[test]
    fn a_family_with_no_kernel_end_is_refused() {
        for p in [proto::NETLINK_FIREWALL, proto::NETLINK_NFLOG, proto::NETLINK_XFRM,
                  proto::NETLINK_ISCSI, proto::NETLINK_FIB_LOOKUP, proto::NETLINK_CONNECTOR,
                  proto::NETLINK_IP6_FW, proto::NETLINK_DNRTMSG, proto::NETLINK_SCSITRANSPORT,
                  proto::NETLINK_ECRYPTFS, proto::NETLINK_RDMA, proto::NETLINK_CRYPTO] {
            assert!(!protocol_registered(p as u32), "protocol {p} has no kernel end");
        }
    }

    #[test]
    fn a_protocol_number_wider_than_the_family_field_is_refused() {
        assert!(!protocol_registered(u32::from(u16::MAX) + 1));
        assert!(!protocol_registered(u32::MAX));
    }
}
