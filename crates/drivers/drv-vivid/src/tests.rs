//! Hosted tests for the virtual camera.
//!
//! Children are bound by explicit path: a bare `mod` inside a `#[path]`-bound
//! module would resolve against this module's directory and name an
//! implementation file instead.
//!
//! Module manifest:
//! - `pattern`: the test-pattern generator's pixel arithmetic.
//! - `pacing`: frame pacing and the transport state machine.

#[path = "tests/pattern.rs"] mod pattern;
#[path = "tests/pacing.rs"] mod pacing;
