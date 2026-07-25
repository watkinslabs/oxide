use super::*;

// Module manifest: support owns shared files; registry owns addressing/listeners;
// stream owns pair/SCM basics; listener_lifecycle owns accept queues;
// recv_transactions owns receive commit/rollback; scm_creds owns credentials;
// scm_gc owns rights graphs/collection; scm_release owns direct release boundaries;
// shutdown owns close/reset semantics; filter owns datagram/seqpacket filtering;
// worker_watch owns the systemd-udevd SOCK_DGRAM completion-delivery contract.
mod support;
use support::anon_file;
use super::test_support::guard as test_guard;
mod registry;
mod stream;
mod listener_lifecycle;
mod recv_transactions;
mod scm_creds;
mod scm_gc;
mod scm_release;
mod shutdown;
mod backpressure;
mod filter;
mod worker_watch;
