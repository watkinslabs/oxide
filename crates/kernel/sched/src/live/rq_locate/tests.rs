// Module manifest:
// - support: isolated runqueue fixture and task constructors.
// - ownership: stable task/rq ownership and class-change coverage.
// - deadline: EDF rekey and CBS preservation coverage.
// - locking: migration interleaving and TaskPi lock coverage.
// - transaction: rejected/unwound mutation, group, migration, and PI coverage.

use super::*;

mod support;
use support::*;
#[path = "tests/ownership.rs"]
mod ownership;
#[path = "tests/deadline.rs"]
mod deadline;
#[path = "tests/locking.rs"]
mod locking;
#[path = "tests/transaction.rs"]
mod transaction;
