use super::*;

#[test]
fn a_triple_fault_is_always_the_last_rung_and_appears_exactly_once() {
    // The ladder only terminates because its final rung cannot be declined.
    // A reordering that moved it earlier would make every later rung dead.
    for available in [true, false] {
        let l = ladder(available);
        assert_eq!(l.last(), Some(&ResetRung::TripleFault));
        assert_eq!(l.iter().filter(|r| **r == ResetRung::TripleFault).count(), 1);
    }
}

#[test]
fn the_firmware_rung_is_attempted_first_and_only_when_a_register_exists() {
    assert_eq!(ladder(true).first(), Some(&ResetRung::Firmware));
    assert!(!ladder(false).contains(&ResetRung::Firmware),
        "a rung with nothing to write must not occupy a place in the ladder");
    // Dropping the rung drops it entirely, it does not shorten the tail.
    assert_eq!(ladder(true).len(), ladder(false).len() + 1);
    assert_eq!(&ladder(true)[1..], ladder(false));
}

#[test]
fn every_rung_appears_at_most_once_in_either_ladder() {
    for available in [true, false] {
        let l = ladder(available);
        for (i, a) in l.iter().enumerate() {
            for b in &l[i + 1..] { assert_ne!(a, b, "a repeated rung would double its settle delay"); }
        }
    }
}

#[test]
fn the_reset_control_request_never_carries_a_reset_code() {
    // The request bit is itself part of the cold-reset code, so the first
    // write legitimately carries it. What it must NOT carry is the rest of
    // the code — those are the bits that turn a request into a reset, and a
    // stale one surviving the mask would fire the port a write early.
    let code_only = RESET_CONTROL_COLD & !RESET_CONTROL_REQUEST;
    assert_ne!(code_only, 0, "the code is wider than the request bit alone");
    for current in 0u8..=255 {
        let (request, fire) = reset_control_writes(current);
        assert_eq!(request & code_only, 0,
            "the request write must not carry the bits that perform the reset");
        assert_eq!(request & RESET_CONTROL_REQUEST, RESET_CONTROL_REQUEST);
        assert_eq!(fire & RESET_CONTROL_COLD, RESET_CONTROL_COLD,
            "the second write is what actually resets");
    }
}

#[test]
fn the_reset_control_writes_preserve_bits_that_are_not_ours() {
    // Chipset bits outside the request/code fields belong to firmware and
    // must survive a read-modify-write.
    let foreign = 0b1010_0000u8;
    let (request, fire) = reset_control_writes(foreign);
    assert_eq!(request & foreign, foreign);
    assert_eq!(fire & foreign, foreign);
}

#[test]
fn a_stale_reset_code_in_the_port_is_cleared_before_the_request() {
    // The read-back already holding the cold-reset code is the case the
    // mask exists for.
    let (request, fire) = reset_control_writes(RESET_CONTROL_COLD);
    assert_eq!(request, RESET_CONTROL_REQUEST);
    assert_eq!(fire, RESET_CONTROL_COLD);
}
