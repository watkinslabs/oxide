// Decisions the network-interface ioctl shim makes before it touches user
// memory: which commands exist, whether each one reads or writes device state,
// the ABI size of the structures they carry, and whether an address the caller
// named is a usable user range.
//
// UNGATED on purpose. `siocgif.rs` is `#![cfg(target_os = "oxide-kernel")]`,
// which every module it declares inherits, so a `#[cfg(test)]` block written
// there compiles to nothing at all and reports as neither run nor skipped
// (`08§7`, `53`). Twelve such cases sat in `siocgif/tests.rs` and had never
// executed once. The parts of that surface which are pure decisions live here
// instead, where `cargo test -p syscalls` compiles and runs them; the gated
// file keeps only the work that genuinely needs user memory and a live device
// table, and calls in here rather than restating any of it.

use hal::USER_VA_END;

pub(crate) const IFNAMSIZ: usize = 16;
// x86_64/aarch64 `struct ifreq`: 16-byte name plus a 24-byte union. The union
// is 24 bytes because the data member is a native pointer; the fixed-width
// members still begin at offset 16.
pub(crate) const IFREQ_SIZE: usize = 40;
pub(crate) const IFCONF_SIZE: usize = 16;

pub(crate) const SIOCGIFNAME:        u64 = 0x8910;
pub(crate) const SIOCSIFLINK:        u64 = 0x8911;
pub(crate) const SIOCGIFCONF:        u64 = 0x8912;
pub(crate) const SIOCGIFFLAGS:       u64 = 0x8913;
pub(crate) const SIOCSIFFLAGS:       u64 = 0x8914;
pub(crate) const SIOCGIFADDR:        u64 = 0x8915;
pub(crate) const SIOCSIFADDR:        u64 = 0x8916;
pub(crate) const SIOCGIFDSTADDR:     u64 = 0x8917;
pub(crate) const SIOCSIFDSTADDR:     u64 = 0x8918;
pub(crate) const SIOCGIFBRDADDR:     u64 = 0x8919;
pub(crate) const SIOCSIFBRDADDR:     u64 = 0x891a;
pub(crate) const SIOCGIFNETMASK:     u64 = 0x891b;
pub(crate) const SIOCSIFNETMASK:     u64 = 0x891c;
pub(crate) const SIOCGIFMETRIC:      u64 = 0x891d;
pub(crate) const SIOCSIFMETRIC:      u64 = 0x891e;
pub(crate) const SIOCGIFMEM:         u64 = 0x891f;
pub(crate) const SIOCSIFMEM:         u64 = 0x8920;
pub(crate) const SIOCGIFMTU:         u64 = 0x8921;
pub(crate) const SIOCSIFMTU:         u64 = 0x8922;
pub(crate) const SIOCSIFNAME:        u64 = 0x8923;
pub(crate) const SIOCSIFHWADDR:      u64 = 0x8924;
pub(crate) const SIOCGIFENCAP:       u64 = 0x8925;
pub(crate) const SIOCSIFENCAP:       u64 = 0x8926;
pub(crate) const SIOCGIFHWADDR:      u64 = 0x8927;
pub(crate) const SIOCGIFSLAVE:       u64 = 0x8929;
pub(crate) const SIOCSIFSLAVE:       u64 = 0x8930;
pub(crate) const SIOCGIFINDEX:       u64 = 0x8933;
pub(crate) const SIOCSIFPFLAGS:      u64 = 0x8934;
pub(crate) const SIOCGIFPFLAGS:      u64 = 0x8935;
pub(crate) const SIOCDIFADDR:        u64 = 0x8936;
pub(crate) const SIOCSIFHWBROADCAST: u64 = 0x8937;
pub(crate) const SIOCGIFCOUNT:       u64 = 0x8938;
pub(crate) const SIOCGIFTXQLEN:      u64 = 0x8942;
pub(crate) const SIOCSIFTXQLEN:      u64 = 0x8943;
pub(crate) const SIOCETHTOOL:        u64 = 0x8946;
pub(crate) const SIOCWANDEV:         u64 = 0x894a;
pub(crate) const SIOCGIFMAP:         u64 = 0x8970;
// Bridge command numbers live here beside the rest so the fall-through order
// below can be checked; `bridge.rs` owns what they DO.
pub(crate) const SIOCBRADDBR:        u64 = 0x89a0;
pub(crate) const SIOCBRDELBR:        u64 = 0x89a1;
pub(crate) const SIOCBRADDIF:        u64 = 0x89a2;
pub(crate) const SIOCBRDELIF:        u64 = 0x89a3;
pub(crate) const SIOCSIFMAP:         u64 = 0x8971;
pub(crate) const SIOCADDRT:          u64 = 0x890B;
pub(crate) const SIOCDELRT:          u64 = 0x890C;
pub(crate) const SIOCDRARP:          u64 = 0x8960;
pub(crate) const SIOCGRARP:          u64 = 0x8961;
pub(crate) const SIOCSRARP:          u64 = 0x8962;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum SiocAccess { Get, Mutate }

/// Whether a command reads device state or changes it, or is not one this
/// shim answers. Drives the socket-descriptor authorisation check, so a
/// command classified as a read may be issued on a descriptor opened for
/// reading and a mutator may not.
///
/// The bridge commands are NOT here: those are classified from the vector the
/// caller passed in user memory, so the gated caller consults that first and
/// falls through to this table.
/// # C: O(1)
pub(crate) fn classify(req: u64) -> Option<SiocAccess> {
    match req {
        SIOCGIFNAME | SIOCGIFCONF | SIOCGIFFLAGS | SIOCGIFADDR
        | SIOCGIFBRDADDR | SIOCGIFDSTADDR | SIOCGIFNETMASK | SIOCGIFMETRIC | SIOCGIFMTU | SIOCGIFHWADDR
        | SIOCGIFMAP
        | SIOCGIFINDEX | SIOCGIFTXQLEN | SIOCGIFPFLAGS | SIOCGIFCOUNT | SIOCGIFSLAVE
        | SIOCSIFLINK | SIOCGIFMEM | SIOCSIFMEM | SIOCGIFENCAP | SIOCSIFENCAP
        | SIOCDRARP | SIOCGRARP | SIOCSRARP | net::uapi::SIOCRTMSG => Some(SiocAccess::Get),
        SIOCWANDEV => Some(SiocAccess::Get),
        SIOCETHTOOL => Some(SiocAccess::Get),
        SIOCSIFFLAGS | SIOCSIFADDR | SIOCSIFBRDADDR | SIOCSIFDSTADDR | SIOCSIFNETMASK
        | SIOCSIFMTU | SIOCSIFHWADDR | SIOCSIFTXQLEN | SIOCADDRT
        | SIOCDELRT | SIOCSIFPFLAGS | SIOCSIFMETRIC | SIOCSIFNAME
        | SIOCDIFADDR | SIOCSIFSLAVE | SIOCSIFMAP | SIOCSIFHWBROADCAST
        | net::arp::uapi::SIOCSARP | net::arp::uapi::SIOCDARP
        | net::uapi::SIOCADDMULTI | net::uapi::SIOCDELMULTI => Some(SiocAccess::Mutate),
        net::arp::uapi::SIOCGARP => Some(SiocAccess::Get),
        _ => None,
    }
}

/// Whether `len` bytes starting at `addr` are a range this shim may copy to
/// or from: a non-null start, and an end that neither wraps nor leaves the
/// user half of the address space.
/// # C: O(1)
pub(crate) fn user_range(addr: u64, len: usize) -> bool {
    addr != 0 && addr.checked_add(len as u64).is_some_and(|end| end <= USER_VA_END)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every command the shim answers is classified, in the direction its name
    /// implies, and one it does not answer is classified as nothing rather
    /// than defaulting into either bucket.
    #[test]
    fn every_answered_command_is_classified_in_the_direction_its_name_implies() {
        const UNKNOWN_SIOC: u64 = 0x89ff;
        for req in [
            SIOCGIFNAME, SIOCGIFCONF, SIOCGIFFLAGS, SIOCGIFADDR,
            SIOCGIFBRDADDR, SIOCGIFDSTADDR, SIOCGIFNETMASK, SIOCGIFMETRIC, SIOCGIFMTU,
            SIOCGIFHWADDR, SIOCGIFINDEX, SIOCGIFTXQLEN, SIOCGIFPFLAGS, SIOCGIFCOUNT,
            SIOCGIFSLAVE, SIOCSIFLINK, SIOCGIFMEM, SIOCSIFMEM, SIOCGIFENCAP, SIOCSIFENCAP,
            SIOCDRARP, SIOCGRARP, SIOCSRARP, net::uapi::SIOCRTMSG, SIOCGIFMAP, SIOCWANDEV,
            net::arp::uapi::SIOCGARP,
        ] { assert_eq!(classify(req), Some(SiocAccess::Get), "{req:#x} reads state"); }
        for req in [
            SIOCSIFFLAGS, SIOCSIFADDR, SIOCSIFBRDADDR, SIOCSIFDSTADDR, SIOCSIFNETMASK,
            SIOCSIFMETRIC, SIOCSIFNAME, SIOCSIFMTU, SIOCSIFHWADDR, SIOCSIFTXQLEN,
            SIOCSIFPFLAGS, SIOCADDRT, SIOCDELRT, SIOCSIFSLAVE, SIOCSIFMAP,
            SIOCSIFHWBROADCAST, SIOCDIFADDR,
            net::arp::uapi::SIOCSARP, net::arp::uapi::SIOCDARP,
            net::uapi::SIOCADDMULTI, net::uapi::SIOCDELMULTI,
        ] { assert_eq!(classify(req), Some(SiocAccess::Mutate), "{req:#x} changes state"); }
        assert_eq!(classify(UNKNOWN_SIOC), None);
    }

    /// The bounded command set that only ever reports state is classified as a
    /// read, so a descriptor opened for reading may issue it.
    #[test]
    fn the_reporting_only_command_set_is_a_read_never_a_mutator() {
        assert_eq!(classify(SIOCETHTOOL), Some(SiocAccess::Get));
    }

    /// Nothing in this table may claim a command the bridge shim owns: the
    /// gated caller consults the bridge FIRST and falls through to here, so a
    /// collision would make the fall-through unreachable for that command.
    #[test]
    fn the_table_claims_nothing_the_bridge_shim_owns() {
        for req in [SIOCBRADDBR, SIOCBRDELBR, SIOCBRADDIF, SIOCBRDELIF] {
            assert_eq!(classify(req), None, "{req:#x} belongs to the bridge shim");
        }
    }

    /// A structure whose ABI size is wrong copies the wrong number of bytes
    /// to or from user memory, so the sizes are pinned rather than derived.
    #[test]
    fn the_abi_structures_are_the_sizes_the_caller_lays_out() {
        assert_eq!(IFREQ_SIZE, 40);
        assert_eq!(IFNAMSIZ, 16);
        // The name, then a union whose largest member is a native pointer
        // beside a 16-byte address.
        assert_eq!(IFREQ_SIZE - IFNAMSIZ - 16, 8);
        assert_eq!(IFCONF_SIZE, 16);
    }

    /// A range check that admits a null start, an end that wraps, or an end
    /// past the user half hands a copy an address the caller does not own.
    #[test]
    fn a_range_is_refused_when_it_is_null_wraps_or_leaves_user_space() {
        assert!(!user_range(0, IFREQ_SIZE), "a null start is never a range");
        assert!(!user_range(u64::MAX - 7, IFREQ_SIZE), "an end that wraps is refused");
        assert!(!user_range(USER_VA_END - IFREQ_SIZE as u64 + 1, IFREQ_SIZE),
            "one byte past the user half is refused");
        assert!(user_range(USER_VA_END - IFREQ_SIZE as u64, IFREQ_SIZE),
            "a range ending exactly at the boundary is admitted");
        assert!(!user_range(USER_VA_END - IFCONF_SIZE as u64 + 1, IFCONF_SIZE),
            "and the same holds for the other structure");
    }
}
