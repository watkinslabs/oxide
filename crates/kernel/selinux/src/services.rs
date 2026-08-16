// The decision engine: everything a caller asks a loaded policy.
//
// Module manifest:
//   av         — access-vector computation, attribute expansion, bounds
//   constraint — postfix constraint evaluation, including every MLS operator
//   transition — the type, role, user and range of a newly created object
//   render     — a context as the string userspace reads
//   parse      — a string from userspace as a context
//   objects    — genfs path contexts and the initial-SID table
//   validtrans — whether an object may move from one label to another
//   fixture    — synthetic policy every test module here builds on (test only)

pub mod av;
pub mod constraint;
pub mod transition;
pub mod render;
pub mod parse;
pub mod objects;
pub mod validtrans;

#[cfg(test)]
#[path = "tests/fixture_policy.rs"]
pub mod fixture;

pub use crate::avc::{AvDecision, AVD_FLAGS_NEVERAUDIT, AVD_FLAGS_PERMISSIVE};

pub use av::{compute_av, MAX_BOUNDS_DEPTH};
pub use constraint::constraint_eval;
pub use transition::{change_sid, compute_sid, is_socket_class, member_sid, transition_sid,
                     TransitionKind, TransitionRequest};
pub use render::{context_to_string, sid_to_context};
pub use parse::{context_from_string, string_to_sid};
pub use objects::{genfs_sid, initial_sid_context, load_initial_sids};
pub use validtrans::validate_transition;
