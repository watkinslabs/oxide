use super::*;

// Module manifest: support owns shared files; registry owns addressing/listeners;
// stream owns pair/SCM basics; listener_lifecycle owns accept queues;
// recv_transactions owns receive commit/rollback; scm_creds owns credentials;
// scm_gc owns rights graphs/collection; shutdown owns close/reset semantics.
mod support;
use support::anon_file;
use super::test_support::guard as test_guard;
mod registry;
mod stream;
mod listener_lifecycle;
mod recv_transactions;
mod scm_creds;
mod scm_gc;
mod shutdown;
