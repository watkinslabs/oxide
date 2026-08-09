// Completion polling (`blk_mq_ops->poll`): the capability predicate and the
// reaped count are separate answers, and the driver reuses the SAME used-ring
// walker the completion softirq runs.
//
// COVERAGE LIMIT, stated rather than faked: the walker itself
// (`drain_owned_completions`) cannot be driven hosted. Its first guard is
// `hhdm() == 0`, and a hosted build has no HHDM, so every hosted call returns
// before it reads a used ring. What IS hosted-testable — and is what a caller
// keys on — is that the capability survives an unprogrammed/idle queue and
// that the count answer stays a count. The walker's own behaviour is covered
// by the chain/chunking tests against the fake ring and by the boot.

use super::*;
use crate::modern::BlkState;

fn state() -> std::sync::Arc<BlkState> {
    let mut cfg = [0u8; 64];
    std::sync::Arc::new(BlkState::for_test_cfg(cfg.as_mut_ptr() as u64))
}

// The reference installs `.poll` in its `blk_mq_ops` for the device, not per
// request: an idle or unprogrammed queue reaps nothing but is still pollable.
// Deriving the capability from "did this poll find work" would refuse a device
// the moment it went quiet.
#[test]
fn the_poll_operation_is_installed_regardless_of_what_a_poll_finds() {
    let s = state();
    assert!(s.can_poll(), "virtio-blk installs a poll operation");
    assert_eq!(s.poll_completions(), 0, "unprogrammed queue reaps nothing");
    assert!(s.can_poll(), "reaping nothing does not revoke the operation");
}

// A synchronous request owns its descriptor and observes `used.idx` itself, so
// the drain must not consume its entry — the same `busy` exclusion the
// completion softirq obeys. A poll that ignored it would eat the completion
// the synchronous waiter is parked on.
#[test]
fn a_poll_does_not_consume_a_synchronous_owners_completion() {
    let s = state();
    s.hold_inflight_for_tests();
    assert_eq!(s.poll_completions(), 0, "the turn holder's entry is left in the ring");
    s.release_inflight_for_tests();
}
