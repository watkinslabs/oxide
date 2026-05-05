// Re-export the hosted-tested tid registry from `crates/sched`.
// Production lives there so the registry's behaviour is locked
// down by hosted tests; this module keeps the kernel-side path
// `crate::sched::registry::*` stable for existing call sites.

#![cfg(target_os = "oxide-kernel")]

pub use sched::registry::{insert, live_tids, lookup, tasks_in_pgrp};
