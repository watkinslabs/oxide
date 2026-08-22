//! Verifier test tree. Manifest only.
//!
//!   support.rs        instruction and map fixtures
//!   cgroup.rs         cgroup skb and sockaddr contracts
//!   socket_filter.rs  socket-filter context, helper and exit contracts
//!   lsm.rs            LSM hook context and return contracts
//!   iter.rs           iterator context and step-answer contracts
//!   raw_tracepoint.rs raw argument slots and attach-cookie helper
//!   perf_event.rs     perf-event register/sample context contract

#[path = "tests/support.rs"]
mod support;

pub(crate) use super::*;
pub(crate) use support::{array, cat, hex, raw};

#[path = "tests/cgroup.rs"]
mod cgroup;
#[path = "tests/socket_filter.rs"]
mod socket_filter;
#[path = "tests/lsm.rs"]
mod lsm;
#[path = "tests/iter.rs"]
mod iter;
#[path = "tests/raw_tracepoint.rs"]
mod raw_tracepoint;
#[path = "tests/perf_event.rs"]
mod perf_event;
