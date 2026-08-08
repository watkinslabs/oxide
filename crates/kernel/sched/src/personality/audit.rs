// Per-bit consumer audit for `personality(2)`.
//
// A persona bit is only correct if the kernel ACTS on it, or if upstream Linux
// does not act on it either. This module is the durable record of which is
// which, so a later reader can tell a bit that is dead upstream from one this
// kernel forgot to wire. Each bit below states its consumer (or the absence of
// one) as an assertion, not as prose that can drift.
//
// Live here, with an owner:
//   UNAME26            `uname(2)` release rewrite            `personality::override_release`
//   ADDR_NO_RANDOMIZE  `PF_RANDOMIZE` for the exec           `aslr::ExecRnd::draw`
//   MMAP_PAGE_ZERO     SVr4 page 0 at `execve`               `elf_load::persona`
//   ADDR_COMPAT_LAYOUT legacy bottom-up mmap arena           `aslr::layout::mmap_is_legacy`
//   READ_IMPLIES_EXEC  `PROT_READ` ⇒ `PROT_EXEC`             mmap / mprotect / shmat
//   STICKY_TIMEOUTS    no residual-timeout writeback         select / pselect6 / ppoll
//   PER_LINUX32        `uname(2)` machine, arm64 EINVAL      uname / slot 135
//
// Dead upstream — stored, round-tripped, rendered by `/proc/<pid>/personality`,
// and read by nothing, because Linux itself reads them nowhere reachable here:
//   FDPIC_FUNCPTRS   arm32 / sh / xtensa signal frames only; neither of this
//                    kernel's arches has an FDPIC ABI or a consumer.
//   SHORT_INODE      no consumer in upstream Linux, on any arch.
//   WHOLE_SECONDS    no consumer in upstream Linux, on any arch.
//   ADDR_LIMIT_3GB   moves the ia32 page offset, read only under a 32-bit
//                    compat task; unreachable on a 64-bit-only kernel.
//   ADDR_LIMIT_32BIT arm32 `STACK_TOP` only; no 64-bit consumer.
//   every PER_* domain byte except PER_LINUX32 — the exec-domain layer that
//                    once dispatched on them no longer exists.

use crate::personality::*;

/// Bits with no consumer in upstream Linux on a 64-bit-only kernel. Stored and
/// reported verbatim; acting on any of them would INVENT behaviour Linux does
/// not have.
pub const PER_NO_CONSUMER: u32 =
    PER_COMPAT_ONLY | FDPIC_FUNCPTRS | SHORT_INODE | WHOLE_SECONDS;

/// Bits this kernel consumes somewhere. The two sets must partition the flag
/// space, or a bit has been added without deciding which it is.
pub const PER_CONSUMED: u32 = UNAME26 | ADDR_NO_RANDOMIZE | MMAP_PAGE_ZERO
    | ADDR_COMPAT_LAYOUT | READ_IMPLIES_EXEC | STICKY_TIMEOUTS;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::personality::domains::{PER_SOLARIS, PER_SVR4, PER_UW7};

    /// Every flag bit the UAPI defines — the top three bytes, `!PER_MASK`
    /// restricted to the assigned range.
    const ALL_FLAGS: u32 = UNAME26 | ADDR_NO_RANDOMIZE | FDPIC_FUNCPTRS | MMAP_PAGE_ZERO
        | ADDR_COMPAT_LAYOUT | READ_IMPLIES_EXEC | ADDR_LIMIT_32BIT | SHORT_INODE
        | WHOLE_SECONDS | STICKY_TIMEOUTS | ADDR_LIMIT_3GB;

    #[test]
    fn every_uapi_flag_is_classified_exactly_once() {
        assert_eq!(PER_CONSUMED & PER_NO_CONSUMER, 0, "a bit is in both classes");
        assert_eq!(PER_CONSUMED | PER_NO_CONSUMER, ALL_FLAGS, "a bit is in neither class");
        assert_eq!(ALL_FLAGS & PER_MASK, 0, "a flag overlaps the domain byte");
        // The two address-size limits are dead for the narrower reason that
        // they are 32-bit-compat only; they must stay a SUBSET of the
        // no-consumer set rather than a second, drifting classification.
        assert_eq!(PER_COMPAT_ONLY & PER_NO_CONSUMER, PER_COMPAT_ONLY);
    }

    #[test]
    fn the_flag_values_are_the_uapi_values() {
        for (got, want) in [
            (UNAME26, 0x0020000u32), (ADDR_NO_RANDOMIZE, 0x0040000),
            (FDPIC_FUNCPTRS, 0x0080000), (MMAP_PAGE_ZERO, 0x0100000),
            (ADDR_COMPAT_LAYOUT, 0x0200000), (READ_IMPLIES_EXEC, 0x0400000),
            (ADDR_LIMIT_32BIT, 0x0800000), (SHORT_INODE, 0x1000000),
            (WHOLE_SECONDS, 0x2000000), (STICKY_TIMEOUTS, 0x4000000),
            (ADDR_LIMIT_3GB, 0x8000000), (PER_MASK, 0x00ff),
        ] { assert_eq!(got, want); }
    }

    /// The dead bits must still SURVIVE a set/read round trip and an `execve`:
    /// `setarch` sets them, `/proc/<pid>/personality` renders them, and a
    /// kernel that silently dropped them would break both.
    #[test]
    fn a_dead_bit_is_stored_round_tripped_and_survives_exec() {
        // Nothing in the exec clear masks touches a no-consumer bit, so the
        // whole set survives both a plain and a privileged exec.
        assert_eq!(PER_NO_CONSUMER & PER_CLEAR_ON_EXEC, 0);
        assert_eq!(PER_NO_CONSUMER & PER_CLEAR_ON_SETID, 0);
        assert_eq!(at_exec(PER_NO_CONSUMER, PER_CLEAR_ON_SETID), PER_NO_CONSUMER);
        // …and no consumer predicate fires for any of them.
        assert!(!mmap_page_zero(PER_NO_CONSUMER));
        assert!(!addr_compat_layout(PER_NO_CONSUMER));
        assert!(!sticky_timeouts(PER_NO_CONSUMER));
        assert_eq!(PER_NO_CONSUMER & UNAME26, 0);
        assert_eq!(PER_NO_CONSUMER & ADDR_NO_RANDOMIZE, 0);
        assert_eq!(PER_NO_CONSUMER & READ_IMPLIES_EXEC, 0);
        // The domain byte of a pure flag set stays PER_LINUX, so no dead flag
        // can smuggle a task into the compat domain.
        assert_eq!(base_domain(PER_NO_CONSUMER), PER_LINUX);
    }

    #[test]
    fn each_consumed_bit_has_a_predicate_that_fires_on_it_alone() {
        assert!(mmap_page_zero(MMAP_PAGE_ZERO));
        assert!(addr_compat_layout(ADDR_COMPAT_LAYOUT));
        assert!(sticky_timeouts(STICKY_TIMEOUTS));
        // …and on nothing else in the flag space.
        assert!(!mmap_page_zero(PER_CONSUMED & !MMAP_PAGE_ZERO));
        assert!(!addr_compat_layout(PER_CONSUMED & !ADDR_COMPAT_LAYOUT));
        assert!(!sticky_timeouts(PER_CONSUMED & !STICKY_TIMEOUTS));
    }

    #[test]
    fn a_composite_domain_carries_the_flags_its_uapi_name_promises() {
        // PER_SVR4 is the reason MMAP_PAGE_ZERO exists: selecting the SVR4
        // domain must arm page 0 AND sticky timeouts through the same word.
        assert!(mmap_page_zero(PER_SVR4));
        assert!(sticky_timeouts(PER_SVR4));
        assert!(mmap_page_zero(PER_UW7));
        assert!(sticky_timeouts(PER_SOLARIS));
        assert!(!mmap_page_zero(PER_SOLARIS));
        // A privileged exec strips SVR4's page 0 but leaves its timeouts —
        // the clear mask is security-relevant bits only.
        let after = at_exec(PER_SVR4, PER_CLEAR_ON_SETID);
        assert!(!mmap_page_zero(after));
        assert!(sticky_timeouts(after));
        assert_eq!(base_domain(after), 0x0001);
    }
}
