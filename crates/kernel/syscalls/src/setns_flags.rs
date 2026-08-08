// `setns(2)` pidfd flag vocabulary — Linux `check_setns_flags`
// and `CLONE_NS_ALL`.
//
// Non-gated so a hosted `cargo test` runs these: `308_setns.rs` is behind
// `kernel_body.rs`'s `#[cfg(target_os = "oxide-kernel")]`, where a
// `#[cfg(test)] mod tests` would compile out silently.

use syscall::errno::Errno;

pub use nscg::proc_ns::{CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS,
                        CLONE_NEWPID, CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS};

/// Linux `CLONE_NS_ALL` — every namespace bit `setns(2)` accepts on a pidfd.
pub const CLONE_NS_ALL: u64 = CLONE_NEWTIME | CLONE_NEWNS | CLONE_NEWCGROUP
    | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET;

/// Install order for a pidfd `setns`, matching `validate_nsset`: the user
/// namespace first (it decides the capability set every later install is
/// judged against), then mount, uts, ipc, pid, cgroup, net, time.
pub const INSTALL_ORDER: [u64; 8] = [
    CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC,
    CLONE_NEWPID, CLONE_NEWCGROUP, CLONE_NEWNET, CLONE_NEWTIME,
];

/// Linux `check_setns_flags`: a pidfd `setns` needs at least one namespace bit
/// and nothing outside `CLONE_NS_ALL`. Zero is EINVAL — unlike the nsfs-fd
/// form, where zero means "whatever type this fd is". # C: O(1)
pub fn check_setns_flags(flags: u64) -> Result<(), Errno> {
    if flags == 0 || (flags & !CLONE_NS_ALL) != 0 { return Err(Errno::Einval); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_einval_on_the_pidfd_form() {
        assert_eq!(check_setns_flags(0), Err(Errno::Einval));
    }

    #[test]
    fn every_namespace_bit_is_accepted_alone_and_together() {
        for b in INSTALL_ORDER { assert_eq!(check_setns_flags(b), Ok(()), "bit {b:#x}"); }
        assert_eq!(check_setns_flags(CLONE_NS_ALL), Ok(()));
    }

    #[test]
    fn bits_outside_clone_ns_all_are_einval() {
        // CLONE_VM / CLONE_FILES / CLONE_THREAD are clone(2) bits, not
        // namespaces; setns must refuse them.
        for b in [0x100u64, 0x400, 0x10000, 1 << 63] {
            assert_eq!(check_setns_flags(b), Err(Errno::Einval), "bit {b:#x}");
            assert_eq!(check_setns_flags(CLONE_NEWNET | b), Err(Errno::Einval));
        }
    }

    #[test]
    fn clone_ns_all_is_exactly_the_eight_namespace_bits() {
        let mut acc = 0u64;
        for b in INSTALL_ORDER { acc |= b; }
        assert_eq!(acc, CLONE_NS_ALL);
        assert_eq!(CLONE_NS_ALL.count_ones(), 8);
    }

    #[test]
    fn user_namespace_installs_first() {
        // It decides the capability set every later install is judged against
        // (`validate_nsset` orders CLONE_NEWUSER ahead of the rest).
        assert_eq!(INSTALL_ORDER[0], CLONE_NEWUSER);
    }

    #[test]
    fn install_order_has_no_duplicates() {
        for i in 0..INSTALL_ORDER.len() {
            for j in i + 1..INSTALL_ORDER.len() {
                assert_ne!(INSTALL_ORDER[i], INSTALL_ORDER[j]);
            }
        }
    }
}
