//! The `AF_INET6` address-write decisions, in a module with no target gate so
//! every one of them is reachable from a hosted test.

/// The errnos the IPv6 address-write path answers with, negated as an rtnetlink
/// ack carries them.
pub(crate) mod errno {
    pub const ENXIO: i32 = -(vfs::VfsError::Enxio as i32);
    pub const EACCES: i32 = -(vfs::VfsError::Eacces as i32);
    pub const EEXIST: i32 = -(vfs::VfsError::Eexist as i32);
    pub const ENODEV: i32 = -(vfs::VfsError::Enodev as i32);
    pub const EINVAL: i32 = -(vfs::VfsError::Einval as i32);
    pub const EADDRNOTAVAIL: i32 = -(vfs::VfsError::Eaddrnotavail as i32);
}

use net::iface_addr::{IFA_F_HOMEADDRESS, IFA_F_MANAGETEMPADDR, IFA_F_MCAUTOJOIN, IFA_F_NODAD,
    IFA_F_NOPREFIXROUTE, INFINITY_LIFE_TIME};

/// The `IFA_F_*` bits a setter may state on an IPv6 address; every other bit it
/// sends is dropped. `IFA_F_OPTIMISTIC` is absent because optimistic DAD is off
/// (the reference clears the bit unless the interface enables it, and no
/// interface here does), and `IFA_F_PERMANENT` is absent because the kernel
/// owns it: it holds exactly while the valid lifetime is infinite.
pub(crate) const USER_FLAG_MASK: u32 = IFA_F_NODAD | IFA_F_HOMEADDRESS | IFA_F_MANAGETEMPADDR
    | IFA_F_NOPREFIXROUTE | IFA_F_MCAUTOJOIN;

/// The prefix length an `IFA_F_MANAGETEMPADDR` address must have: temporary
/// addresses are generated from a 64-bit interface identifier.
pub(crate) const MANAGETEMPADDR_PREFIXLEN: u8 = 64;

/// The valid and preferred lifetimes an add or replace applies, in seconds.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Lifetimes {
    pub(crate) preferred: u32,
    pub(crate) valid: u32,
}

impl Lifetimes {
    /// Resolve `IFA_CACHEINFO` into the two lifetimes, or `None` for the
    /// attribute the reference rejects: a zero valid lifetime, or a preferred
    /// lifetime outliving the valid one. Absent, both lifetimes are infinite.
    /// # C: O(1)
    pub(crate) fn from_cacheinfo(cacheinfo: Option<(u32, u32)>) -> Option<Self> {
        let Some((preferred, valid)) = cacheinfo else {
            return Some(Self { preferred: INFINITY_LIFE_TIME, valid: INFINITY_LIFE_TIME });
        };
        if valid == 0 || preferred > valid { return None; }
        Some(Self { preferred, valid })
    }

    /// The address is permanent while nothing expires it. # C: O(1)
    pub(crate) fn permanent(&self) -> bool { self.valid == INFINITY_LIFE_TIME }
}

/// The classification the reference screens a new address by.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum AddrType {
    Unspecified,
    Multicast,
    Loopback,
    Unicast,
}

impl AddrType {
    /// # C: O(1)
    pub(crate) fn of(addr: net::Ipv6Addr) -> Self {
        if addr.is_unspecified() { return Self::Unspecified; }
        if addr.is_multicast() { return Self::Multicast; }
        if addr.is_loopback() { return Self::Loopback; }
        Self::Unicast
    }
}

/// Reject the addresses no interface may hold. All three answer
/// `EADDRNOTAVAIL`: the unspecified address, a multicast group the setter did
/// not ask to auto-join, and the loopback address on anything but a loopback
/// interface. A link-local unicast address is ordinary here — nothing rejects
/// it, and its scope is derived from the address when it is reported.
/// # C: O(1)
pub(crate) fn reject_address_type(kind: AddrType, user_flags: u32, loopback_dev: bool)
    -> Option<i32>
{
    match kind {
        AddrType::Unspecified => Some(errno::EADDRNOTAVAIL),
        AddrType::Multicast if user_flags & IFA_F_MCAUTOJOIN == 0 => Some(errno::EADDRNOTAVAIL),
        AddrType::Loopback if !loopback_dev => Some(errno::EADDRNOTAVAIL),
        _ => None,
    }
}

/// A managed-temporary-address prefix must be a /64. # C: O(1)
pub(crate) fn reject_manage_tempaddr(user_flags: u32, prefixlen: u8) -> Option<i32> {
    if user_flags & IFA_F_MANAGETEMPADDR != 0 && prefixlen != MANAGETEMPADDR_PREFIXLEN {
        return Some(errno::EINVAL);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::iface_addr::{IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_OPTIMISTIC, IFA_F_PERMANENT,
        IFA_F_SECONDARY, IFA_F_STABLE_PRIVACY, IFA_F_TENTATIVE};

    #[test]
    fn errnos_match_the_linux_numbers() {
        assert_eq!(errno::ENXIO, -6);
        assert_eq!(errno::EACCES, -13);
        assert_eq!(errno::EEXIST, -17);
        assert_eq!(errno::ENODEV, -19);
        assert_eq!(errno::EINVAL, -22);
        assert_eq!(errno::EADDRNOTAVAIL, -99);
    }

    // The setter owns NODAD, HOMEADDRESS, MANAGETEMPADDR, NOPREFIXROUTE and
    // MCAUTOJOIN. Every other bit it sends is dropped, including the ones the
    // kernel derives, so a caller cannot declare its own address already
    // verified, already failed, or permanent past its lifetime.
    #[test]
    fn only_the_setter_owned_flags_survive_the_mask() {
        for kernel_owned in [IFA_F_SECONDARY, IFA_F_DADFAILED, IFA_F_DEPRECATED,
            IFA_F_TENTATIVE, IFA_F_PERMANENT, IFA_F_OPTIMISTIC, IFA_F_STABLE_PRIVACY]
        {
            assert_eq!(kernel_owned & USER_FLAG_MASK, 0, "flag {kernel_owned:#x} is not the setter's");
        }
        assert_eq!(u32::MAX & USER_FLAG_MASK,
            IFA_F_NODAD | IFA_F_HOMEADDRESS | IFA_F_MANAGETEMPADDR | IFA_F_NOPREFIXROUTE
                | IFA_F_MCAUTOJOIN);
    }

    #[test]
    fn absent_cacheinfo_is_an_infinite_permanent_lifetime() {
        let lifetimes = Lifetimes::from_cacheinfo(None).unwrap();
        assert_eq!(lifetimes, Lifetimes { preferred: INFINITY_LIFE_TIME,
            valid: INFINITY_LIFE_TIME });
        assert!(lifetimes.permanent());
    }

    #[test]
    fn a_zero_valid_lifetime_or_preferred_past_valid_is_einval() {
        assert!(Lifetimes::from_cacheinfo(Some((0, 0))).is_none());
        assert!(Lifetimes::from_cacheinfo(Some((30, 0))).is_none());
        assert!(Lifetimes::from_cacheinfo(Some((601, 600))).is_none());
        assert_eq!(Lifetimes::from_cacheinfo(Some((600, 600))),
            Some(Lifetimes { preferred: 600, valid: 600 }));
        assert_eq!(Lifetimes::from_cacheinfo(Some((0, 600))),
            Some(Lifetimes { preferred: 0, valid: 600 }));
    }

    // A finite valid lifetime is what strips IFA_F_PERMANENT; an infinite
    // valid lifetime keeps it even when the preferred lifetime is finite.
    #[test]
    fn permanence_follows_the_valid_lifetime_alone() {
        assert!(Lifetimes::from_cacheinfo(Some((0, INFINITY_LIFE_TIME))).unwrap().permanent());
        assert!(!Lifetimes::from_cacheinfo(Some((600, 600))).unwrap().permanent());
        assert!(!Lifetimes::from_cacheinfo(Some((1, u32::MAX - 1))).unwrap().permanent());
    }

    #[test]
    fn unassignable_addresses_are_eaddrnotavail() {
        let unspecified = net::Ipv6Addr([0u8; 16]);
        assert_eq!(AddrType::of(unspecified), AddrType::Unspecified);
        assert_eq!(reject_address_type(AddrType::Unspecified, IFA_F_MCAUTOJOIN, true),
            Some(errno::EADDRNOTAVAIL));

        let mut group = [0u8; 16];
        group[0] = 0xff; group[1] = 0x02; group[15] = 1;
        assert_eq!(AddrType::of(net::Ipv6Addr(group)), AddrType::Multicast);
        assert_eq!(reject_address_type(AddrType::Multicast, 0, false),
            Some(errno::EADDRNOTAVAIL));
        // MCAUTOJOIN is the one way to hold a multicast address.
        assert_eq!(reject_address_type(AddrType::Multicast, IFA_F_MCAUTOJOIN, false), None);

        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        assert_eq!(AddrType::of(net::Ipv6Addr(loopback)), AddrType::Loopback);
        assert_eq!(reject_address_type(AddrType::Loopback, 0, false),
            Some(errno::EADDRNOTAVAIL));
        assert_eq!(reject_address_type(AddrType::Loopback, 0, true), None);
    }

    // The address in the reported failure. A link-local unicast address is
    // assignable on an ordinary interface; nothing about its scope rejects it.
    #[test]
    fn a_link_local_unicast_address_is_assignable() {
        let mut link_local = [0u8; 16];
        link_local[0] = 0xfe; link_local[1] = 0x80;
        link_local[8..].copy_from_slice(&[0xca, 0x67, 0xcf, 0xc6, 0xb1, 0x78, 0x90, 0x02]);
        let addr = net::Ipv6Addr(link_local);
        assert!(addr.is_link_local());
        assert_eq!(AddrType::of(addr), AddrType::Unicast);
        assert_eq!(reject_address_type(AddrType::Unicast, 0, false), None);
    }

    #[test]
    fn managetempaddr_demands_a_64_bit_prefix() {
        assert_eq!(reject_manage_tempaddr(IFA_F_MANAGETEMPADDR, 64), None);
        assert_eq!(reject_manage_tempaddr(IFA_F_MANAGETEMPADDR, 128), Some(errno::EINVAL));
        assert_eq!(reject_manage_tempaddr(IFA_F_MANAGETEMPADDR, 0), Some(errno::EINVAL));
        // The ceiling only applies to the flag that asks for it.
        assert_eq!(reject_manage_tempaddr(0, 128), None);
    }
}
