use vfs::Ino;

/// Per-object-kind inode identities for the fds `bpf(2)` hands back. The base
/// was 0x7300_0000, which timerfd mints from — a bpf prog fd and the third
/// timerfd a process created carried the same number. It now comes from the
/// one range `vfs::pseudo_ino` reserves for bpf, and the const overlap check
/// there fails the build if a second owner claims it. Low bits unchanged.
const INO_BASE: Ino = vfs::pseudo_ino::BPF.start();
pub(crate) const INO_PROG: Ino = INO_BASE | 0x01;
pub(crate) const INO_MAP: Ino = INO_BASE | 0x02;
pub(crate) const INO_LINK: Ino = INO_BASE | 0x03;
pub(crate) const INO_BTF: Ino = INO_BASE | 0x04;
pub(crate) const INO_TOKEN: Ino = INO_BASE | 0x05;
pub(crate) const INO_STATS: Ino = INO_BASE | 0x06;

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::pseudo_ino::{BPF, TIMERFD};

    /// The collision: bpf minted from 0x7300_0000, timerfd's base. A bpf prog
    /// fd and a process's third timerfd carried the same number, and both
    /// families' handlers were reached by testing that number.
    #[test]
    fn bpf_numbers_no_longer_intersect_timerfd() {
        assert!(!vfs::pseudo_ino::overlaps(&BPF, &TIMERFD));
        for ino in [INO_PROG, INO_MAP, INO_LINK, INO_BTF, INO_TOKEN, INO_STATS] {
            assert!(BPF.contains(ino), "{ino:#x} outside the bpf region");
            assert!(!TIMERFD.contains(ino), "{ino:#x} is a timerfd number");
        }
    }

    /// Low bits unchanged by the move — one per object kind, all distinct.
    #[test]
    fn each_object_kind_keeps_its_own_low_bits() {
        let all = [INO_PROG, INO_MAP, INO_LINK, INO_BTF, INO_TOKEN, INO_STATS];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] { assert_ne!(a, b); }
            assert_eq!(a & !BPF.start(), (i + 1) as Ino);
        }
    }
}
