//! Native thread factory: creation owns admission, context owns continuation,
//! lifecycle owns attach/publication/cleanup; dispatch decodes private operations.
mod creation;
mod context;
mod lifecycle;
mod dispatch;
pub(crate) use creation::{begin, factory};
pub(crate) use dispatch::dispatch;
pub(crate) use lifecycle::{request_termination, exit_to_user, cleanup_at_exit};
