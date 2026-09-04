// Module manifest:
// - handoff: rq-lock handoff and IRQ-state restoration coverage.
// - class_change_accounting: cross-class execution-accounting coverage.

use super::*;

#[path = "tests/handoff.rs"]
mod handoff;
#[path = "tests/class_change_accounting.rs"]
mod class_change_accounting;
