// User-buffer range coverage — the DECISION half of `userbuf`'s
// `validate_user_buf_{readable,writable}`, ungated so its tests compile
// (`userbuf.rs` is `#![cfg(target_os = "oxide-kernel")]`).
//
// Linux's `access_ok` is O(1) — a bound check against `TASK_SIZE_MAX`
// — because per-page validity is resolved by
// the fault handler through the exception table during the copy itself. This
// port has no kernel extable, so `userbuf` pre-validates that the range is
// covered by VMAs with the right protection. That is a legitimate substitute,
// but the walk must be over VMAs, not over PAGES: a page-at-a-time loop is
// O(len / 4096) with interrupts masked, and a caller passing a multi-hundred-GB
// length wedges its CPU for minutes — no tick, no TLB-shootdown ACK, so the
// shootdown sender on the peer CPU spins too. B1476 caught exactly that: CPU1
// parked at a fixed rip inside `validate_user_buf_writable` for 300+ s while
// CPU0 reported `[TLB-STUCK] pending=0x2` against it every escalation.
//
// Walking VMAs makes it O(N_vmas spanning the range) — 1 for the overwhelmingly
// common single-mapping case, and bounded by the address space's VMA count in
// the worst case, which no user argument can inflate.

/// Page size the walk steps on. VMA bounds are page-aligned, so the walk never
/// needs a finer granularity than this.
const PAGE: u64 = 0x1000;

/// What a probe found at one address: the covering VMA's exclusive end, and
/// whether its protection admits the access being validated.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Span {
    /// Exclusive end of the covering VMA.
    pub end:     u64,
    /// Whether that VMA carries the required `VmaProt` bit.
    pub allowed: bool,
}

/// Whether `[ptr, ptr + len)` is entirely covered by VMAs the probe accepts.
/// `probe(va)` answers for the VMA CONTAINING `va` (Linux `find_vma` semantics
/// as this port implements them — `find_containing`), or `None` for a hole.
///
/// `len == 0` is vacuously covered, matching Linux, where a zero-length
/// `copy_to_user` touches nothing.
/// # C: O(N_vmas spanning the range)
pub fn range_covered(ptr: u64, len: u64, mut probe: impl FnMut(u64) -> Option<Span>) -> bool {
    if len == 0 { return true; }
    let Some(end_inclusive) = ptr.checked_add(len).and_then(|e| e.checked_sub(1)) else { return false };
    let last = end_inclusive & !(PAGE - 1);
    let mut va = ptr & !(PAGE - 1);
    loop {
        let Some(span) = probe(va) else { return false };
        if !span.allowed { return false; }
        // A containing VMA always ends above the probed address. Refusing a
        // non-advancing span keeps a malformed tree from spinning this loop
        // forever — the exact failure class this walk exists to remove.
        if span.end <= va { return false; }
        if span.end > last { return true; }
        va = span.end & !(PAGE - 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A probe over a sorted list of `(start, end, allowed)` VMAs.
    fn vmas(list: &[(u64, u64, bool)]) -> impl FnMut(u64) -> Option<Span> + '_ {
        move |va| list.iter().find(|(s, e, _)| va >= *s && va < *e)
                     .map(|(_, e, ok)| Span { end: *e, allowed: *ok })
    }

    #[test]
    fn one_mapping_covers_any_length_in_one_probe() {
        let map = [(0x1000u64, 0x100000u64, true)];
        let mut probes = 0;
        let covered = range_covered(0x1000, 0xFF000, |va| { probes += 1; vmas(&map)(va) });
        assert!(covered);
        assert_eq!(probes, 1, "a single covering VMA must cost exactly one probe");
    }

    #[test]
    fn a_huge_length_does_not_cost_a_probe_per_page() {
        // The B1476 wedge: ~8e11 bytes is 2e8 pages. One probe, not 2e8.
        let map = [(0x7f416efbf000u64, 0x800000000000u64, true)];
        let mut probes = 0;
        let covered = range_covered(0x7f416efbf000, 0x800000000000 - 0x7f416efbf000,
                                    |va| { probes += 1; vmas(&map)(va) });
        assert!(covered);
        assert_eq!(probes, 1);
    }

    #[test]
    fn adjacent_mappings_are_walked_one_probe_each() {
        let map = [(0x1000u64, 0x2000u64, true), (0x2000u64, 0x4000u64, true)];
        let mut probes = 0;
        assert!(range_covered(0x1000, 0x3000, |va| { probes += 1; vmas(&map)(va) }));
        assert_eq!(probes, 2);
    }

    #[test]
    fn a_hole_between_mappings_is_not_covered() {
        let map = [(0x1000u64, 0x2000u64, true), (0x3000u64, 0x4000u64, true)];
        assert!(!range_covered(0x1000, 0x3000, vmas(&map)), "the gap at 0x2000 must fail");
        assert!(range_covered(0x1000, 0x1000, vmas(&map)), "wholly inside the first is fine");
    }

    #[test]
    fn a_mapping_without_the_required_protection_fails() {
        let map = [(0x1000u64, 0x2000u64, true), (0x2000u64, 0x4000u64, false)];
        assert!(range_covered(0x1000, 0x1000, vmas(&map)));
        assert!(!range_covered(0x1000, 0x1001, vmas(&map)), "crossing into the RO map fails");
    }

    #[test]
    fn an_unmapped_start_fails_without_walking() {
        assert!(!range_covered(0x1000, 0x1000, |_| None));
    }

    #[test]
    fn zero_length_is_covered_and_probes_nothing() {
        let mut probes = 0;
        assert!(range_covered(0, 0, |_| { probes += 1; None }));
        assert_eq!(probes, 0);
    }

    #[test]
    fn a_length_that_overflows_the_address_is_refused() {
        assert!(!range_covered(u64::MAX, 2, |_| Some(Span { end: u64::MAX, allowed: true })));
    }

    #[test]
    fn a_non_advancing_span_cannot_spin_the_walk() {
        // A malformed tree reporting `end <= va` must terminate, not loop.
        assert!(!range_covered(0x2000, 0x1000, |_| Some(Span { end: 0x1000, allowed: true })));
        assert!(!range_covered(0x2000, 0x1000, |va| Some(Span { end: va, allowed: true })));
    }

    #[test]
    fn an_unaligned_start_still_validates_its_own_page() {
        let map = [(0x1000u64, 0x2000u64, true)];
        assert!(range_covered(0x1abc, 4, vmas(&map)));
        assert!(!range_covered(0x1ffc, 8, vmas(&map)), "spilling into the next page fails");
    }
}
