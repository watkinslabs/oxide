// Which CPU exceptions take the paranoid entry, and which IST stack each of
// them runs on. Ungated so the table is unit-testable: the set is a
// correctness contract shared by two places that cannot see each other —
// `idt::install_ist_gates` (Rust) and the `VECNEP`/`VECEP` stub macros
// (`fault/stubs.rs`, `global_asm!`).
//
// A vector in one and not the other is silently wrong in a specific way:
// IST-routed but not paranoid ⇒ an exception arriving in the exit-path
// `swapgs` window trusts the saved CS, reads kernel CS and runs the handler
// on the USER GS base; paranoid but not IST-routed ⇒ the entry pays an
// `rdmsr` it never needed.

use crate::tss::{IST_DB, IST_DF, IST_MC, IST_NMI};

/// Intel SDM Vol. 3 §6.15 vector assignments for the four exceptions that
/// can fire at CPL 0 while GS still holds the user base.
pub const VEC_DB: u8 = 1;
pub const VEC_NMI: u8 = 2;
pub const VEC_DF: u8 = 8;
pub const VEC_MC: u8 = 18;

/// `(vector, IST slot)` for every paranoid exception. Linux's assignment:
/// #DF→IST1, NMI→IST2, #DB→IST3, #MC→IST4. #PF is deliberately absent —
/// page faults nest legitimately and a single per-CPU IST is not reentrant.
pub const PARANOID_VECTORS: [(u8, u8); 4] =
    [(VEC_DB, IST_DB), (VEC_NMI, IST_NMI), (VEC_DF, IST_DF), (VEC_MC, IST_MC)];

#[cfg(test)]
mod tests {
    use super::*;

    fn is_paranoid(vec: u8) -> bool { PARANOID_VECTORS.iter().any(|&(v, _)| v == vec) }

    #[test]
    fn the_paranoid_set_is_exactly_the_four_ist_routed_vectors() {
        // Pinned against `fault/stubs.rs`, where these four — and only these
        // four — use the VECNEP/VECEP macros, and against the named vector
        // numbers so a renumbering has to break here first.
        assert_eq!(PARANOID_VECTORS.map(|(v, _)| v), [1, 2, 8, 18]);
        assert_eq!((VEC_DB, VEC_NMI, VEC_DF, VEC_MC), (1, 2, 8, 18));
        assert_eq!((0u8..=255).filter(|&v| is_paranoid(v)).count(), 4);
    }

    #[test]
    fn every_paranoid_vector_gets_a_distinct_nonzero_ist_slot() {
        // A zero `ist` field means "use RSP0" — i.e. not IST-routed at all —
        // and two vectors sharing a slot would corrupt each other's stack the
        // moment one nested inside the other.
        let mut seen = [false; 8];
        for (vec, ist) in PARANOID_VECTORS {
            assert!(ist >= 1 && ist <= 7, "vector {vec} ist {ist} out of range");
            assert!(!seen[ist as usize], "ist {ist} used twice");
            seen[ist as usize] = true;
        }
    }

    #[test]
    fn the_faults_that_stay_on_the_regular_entry() {
        // The two that most often get mis-added: #PF (14) nests and must keep
        // RSP0, #BP (3) is a DPL-3 gate reachable only from ring 3, where the
        // saved-CS test is exact.
        assert!(!is_paranoid(14));
        assert!(!is_paranoid(3));
        assert!(!is_paranoid(13));
        assert!(!is_paranoid(0));
    }
}
