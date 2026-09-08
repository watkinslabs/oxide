//! What one builtin-ELF unwind attempt answers.
//!
//! The runtime's unwinder asks this slot before it uses its own PE unwinder,
//! and falls back to that unwinder for exactly one status. Any other status is
//! taken as the unwind's own authoritative result and propagated out of the
//! frame walk, which aborts the exception dispatch that asked. An attempt that
//! did not unwind therefore has one status available to it, whatever the
//! reason was.

/// The frame was unwound and the caller's context and dispatch record hold the
/// result.
pub const STATUS_SUCCESS: u64 = 0;
/// The only status the caller reads as "not a builtin frame, use your own
/// unwinder". Every refusal answers this.
pub const STATUS_UNSUCCESSFUL: u64 = 0xc000_0001;

/// Why one attempt did not produce an unwound frame. The reason names the
/// refusal for diagnostics; it never changes the answer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnwindRefusal {
    /// The request envelope was absent, malformed, or named an unknown type.
    MalformedRequest,
    /// No caller identity, or the caller is not a runtime thread.
    NoCaller,
    /// The program counter belongs to no loaded native module.
    NoModule,
    /// The module has no frame description covering the program counter.
    NoFrameDescription,
    /// A frame description was found but could not be read or evaluated.
    MalformedFrameProgram,
    /// The caller's context or dispatch record could not be read or written.
    InaccessibleRecord,
    /// This machine has no builtin-frame unwinder.
    UnsupportedMachine,
}

/// The status one attempt answers.
/// # C: O(1)
pub const fn unwind_status(outcome: Result<(), UnwindRefusal>) -> u64 {
    match outcome { Ok(()) => STATUS_SUCCESS, Err(_) => STATUS_UNSUCCESSFUL }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFUSALS: [UnwindRefusal; 7] = [
        UnwindRefusal::MalformedRequest, UnwindRefusal::NoCaller, UnwindRefusal::NoModule,
        UnwindRefusal::NoFrameDescription, UnwindRefusal::MalformedFrameProgram,
        UnwindRefusal::InaccessibleRecord, UnwindRefusal::UnsupportedMachine,
    ];

    #[test]
    fn an_unwound_frame_answers_success() {
        assert_eq!(unwind_status(Ok(())), STATUS_SUCCESS);
    }

    #[test]
    fn every_refusal_answers_the_one_status_the_caller_falls_back_on() {
        assert_eq!(REFUSALS.len(), 7);
        for refusal in REFUSALS {
            assert_eq!(unwind_status(Err(refusal)), STATUS_UNSUCCESSFUL,
                "{refusal:?} answered a status the caller would propagate instead of falling back");
        }
    }

    #[test]
    fn no_refusal_answers_a_status_the_caller_would_propagate() {
        // The caller returns any status other than the fallback one straight
        // out of its frame walk. Invalid-parameter and invalid-disposition are
        // the two this slot used to answer; neither may appear again.
        const PROPAGATED: [u64; 2] = [0xc000_000d, 0xc000_0026];
        for refusal in REFUSALS {
            assert!(!PROPAGATED.contains(&unwind_status(Err(refusal))));
        }
    }
}
