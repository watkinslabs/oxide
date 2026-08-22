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
pub mod bounds;

#[cfg(test)]
#[path = "tests/fixture_policy.rs"]
pub mod fixture;

pub use crate::avc::{AvDecision, AVD_FLAGS_NEVERAUDIT, AVD_FLAGS_PERMISSIVE};

pub use av::{compute_av, compute_av_user, MAX_BOUNDS_DEPTH};
pub use constraint::constraint_eval;
pub use transition::{change_sid, change_sid_user, compute_sid, is_socket_class, member_sid,
                     member_sid_user, transition_sid, transition_sid_user, ClassValue,
                     TransitionKind, TransitionRequest};
pub use render::{context_to_string, sid_to_context, sid_to_context_force};
pub use parse::{context_from_string, string_to_sid};
pub use objects::{genfs_sid, initial_sid_context, load_initial_sids};
pub use validtrans::{validate_transition, validate_transition_user};
pub use bounds::bounded_transition;

#[cfg(test)]
#[path = "tests/bounds.rs"]
mod bounds_tests;
