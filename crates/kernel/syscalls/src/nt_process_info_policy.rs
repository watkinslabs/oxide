//! Hosted-testable answers for the fixed-width native process-information
//! classes the runtime asks during its own initialization.

/// Information classes answered here.
pub const DEBUG_PORT: u32 = 7;
pub const DEFAULT_HARD_ERROR_MODE: u32 = 12;
pub const SESSION_INFORMATION: u32 = 24;
pub const COOKIE: u32 = 36;

const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;

const POINTER_BYTES: usize = 8;
const WORD_BYTES: usize = 4;

/// No debugger is attached to a process the kernel started: the port reads
/// back as zero with a successful status, which is what distinguishes it from
/// a query that failed.
pub const NO_DEBUG_PORT: u64 = 0;
/// A process starts with hard-error reporting fully enabled; the mode only
/// leaves this value when the process sets it.
pub const INITIAL_HARD_ERROR_MODE: u32 = 0;

/// One fixed-width answer: the little-endian bytes to publish.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Answer {
    Pointer(u64),
    Word(u32),
}

impl Answer {
    /// Byte width of the published record. # C: O(1)
    pub const fn bytes(self) -> usize {
        match self { Answer::Pointer(_) => POINTER_BYTES, Answer::Word(_) => WORD_BYTES }
    }
}

/// Per-process facts the fixed-width classes report.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Facts {
    pub debug_port: u64,
    pub hard_error_mode: u32,
    pub session_id: u32,
    pub cookie: u32,
}

/// Decide one fixed-width process-information query.
///
/// `None` means the class is not one of these; the caller keeps looking. The
/// cookie is readable only through the caller's own process: naming another
/// process is a parameter error rather than an access error, and that check
/// precedes the length check.
/// # C: O(1)
pub fn answer(class: u32, length: usize, info: u64, current_process: bool, facts: &Facts)
    -> Option<Result<Answer, u64>> {
    let answer = match class {
        DEBUG_PORT => Answer::Pointer(facts.debug_port),
        DEFAULT_HARD_ERROR_MODE => Answer::Word(facts.hard_error_mode),
        SESSION_INFORMATION => Answer::Word(facts.session_id),
        COOKIE => {
            if !current_process { return Some(Err(STATUS_INVALID_PARAMETER)); }
            Answer::Word(facts.cookie)
        }
        _ => return None,
    };
    if length != answer.bytes() { return Some(Err(STATUS_INFO_LENGTH_MISMATCH)); }
    if info == 0 { return Some(Err(STATUS_ACCESS_VIOLATION)); }
    Some(Ok(answer))
}

/// Derive one process's pointer-obfuscation cookie from a kernel-wide secret
/// and the process's own randomized block address.
///
/// The value must be stable for the life of the process and must never be
/// zero: a zero cookie is indistinguishable from an unanswered query, and the
/// runtime then re-queries on every pointer it encodes.
/// # C: O(1)
pub fn cookie(seed: u64, peb: u64) -> u32 {
    let mut mixed = seed ^ peb.rotate_left(17);
    mixed = mixed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    mixed ^= mixed >> 32;
    let value = mixed as u32;
    if value == 0 { 1 } else { value }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts { Facts { debug_port: NO_DEBUG_PORT, hard_error_mode: INITIAL_HARD_ERROR_MODE, session_id: 0, cookie: 0x1234_5678 } }

    #[test]
    fn unrelated_classes_are_left_to_their_own_owner() {
        assert_eq!(answer(0, 48, 0x1000, true, &facts()), None);
        assert_eq!(answer(37, 64, 0x1000, true, &facts()), None);
    }

    #[test]
    fn debug_port_reports_no_debugger_in_pointer_width() {
        assert_eq!(answer(DEBUG_PORT, 8, 0x1000, true, &facts()), Some(Ok(Answer::Pointer(0))));
        assert_eq!(answer(DEBUG_PORT, 4, 0x1000, true, &facts()), Some(Err(STATUS_INFO_LENGTH_MISMATCH)));
    }

    #[test]
    fn word_width_classes_reject_a_pointer_width_buffer() {
        for class in [DEFAULT_HARD_ERROR_MODE, SESSION_INFORMATION, COOKIE] {
            assert_eq!(answer(class, 8, 0x1000, true, &facts()), Some(Err(STATUS_INFO_LENGTH_MISMATCH)));
            assert!(matches!(answer(class, 4, 0x1000, true, &facts()), Some(Ok(Answer::Word(_)))));
        }
    }

    #[test]
    fn a_named_process_cannot_read_the_cookie_even_at_the_right_width() {
        assert_eq!(answer(COOKIE, 4, 0x1000, false, &facts()), Some(Err(STATUS_INVALID_PARAMETER)));
        // The identity check precedes the length check.
        assert_eq!(answer(COOKIE, 8, 0x1000, false, &facts()), Some(Err(STATUS_INVALID_PARAMETER)));
    }

    #[test]
    fn a_null_buffer_at_the_right_width_is_an_access_violation() {
        assert_eq!(answer(DEBUG_PORT, 8, 0, true, &facts()), Some(Err(STATUS_ACCESS_VIOLATION)));
        assert_eq!(answer(SESSION_INFORMATION, 4, 0, true, &facts()), Some(Err(STATUS_ACCESS_VIOLATION)));
    }

    #[test]
    fn hard_error_mode_and_session_report_their_initial_values() {
        assert_eq!(answer(DEFAULT_HARD_ERROR_MODE, 4, 0x1000, true, &facts()), Some(Ok(Answer::Word(0))));
        assert_eq!(answer(SESSION_INFORMATION, 4, 0x1000, true, &facts()), Some(Ok(Answer::Word(0))));
    }

    #[test]
    fn a_cookie_is_stable_per_process_never_zero_and_not_the_block_address() {
        let seed = 0x0123_4567_89ab_cdef;
        for peb in [0x1000u64, 0x7fff_0000_0000, 0, u64::MAX] {
            let value = cookie(seed, peb);
            assert_eq!(value, cookie(seed, peb));
            assert_ne!(value, 0);
            assert_ne!(value as u64, peb);
        }
    }

    #[test]
    fn distinct_processes_and_distinct_secrets_produce_distinct_cookies() {
        let seed = 0x0123_4567_89ab_cdef;
        assert_ne!(cookie(seed, 0x140_0000), cookie(seed, 0x141_0000));
        assert_ne!(cookie(seed, 0x140_0000), cookie(seed ^ 1, 0x140_0000));
    }

    #[test]
    fn positive_control_a_truncating_derivation_would_leak_the_block_address() {
        // The pre-fix shape this replaces: the low word of the block address.
        let leak = |peb: u64| peb as u32;
        assert_eq!(leak(0x140_0000), 0x140_0000);
        assert_ne!(cookie(0, 0x140_0000), leak(0x140_0000));
    }
}
