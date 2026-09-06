//! Completion routing; each transaction owner retains its own pending command.
use super::{create, position, send};

pub(crate) fn complete_callback(completion: sched::nt_callback::Completion, result: u64) -> u64 {
    if send::handles_callback(completion.kind) { send::complete_callback(completion, result) }
    else if position::handles_callback(completion.kind) { position::complete_position_callback(completion, result) }
    else { create::complete_callback(completion, result) }
}
