// Module manifest: position's target-independent continuation decode and nonclient-calc policy,
// mirrored for hosted compilation; the live and remote adapters stay gated in position.rs.
#[path = "continuation.rs"]
pub(crate) mod continuation;
#[path = "nccalc.rs"]
pub(crate) mod nccalc;
pub(crate) use continuation::Outcome;
