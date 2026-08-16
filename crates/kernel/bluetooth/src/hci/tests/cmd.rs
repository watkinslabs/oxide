use super::*;
use crate::uapi::hci_cmd::{HCI_OP_READ_BD_ADDR, HCI_OP_RESET};

fn queued(q: &mut CmdQueue, opcode: u16) { q.enqueue(opcode, alloc::vec::Vec::new()); }

#[test]
fn a_fresh_queue_holds_exactly_one_credit() {
    assert_eq!(CmdQueue::new().credits(), 1);
}

#[test]
fn sending_spends_the_credit_and_a_second_send_is_refused() {
    let mut q = CmdQueue::new();
    queued(&mut q, HCI_OP_RESET);
    queued(&mut q, HCI_OP_READ_BD_ADDR);
    assert_eq!(q.dequeue(0).unwrap().opcode, HCI_OP_RESET);
    assert_eq!(q.credits(), 0);
    assert!(q.dequeue(0).is_none());
    assert_eq!(q.pending(), 1);
}

// A completion restores the allowance to exactly one. A controller reporting
// the same completion twice must NOT leave the host with two credits: the
// second command would overrun the controller's own command buffer.
#[test]
fn a_repeated_completion_cannot_inflate_the_allowance() {
    let mut q = CmdQueue::new();
    queued(&mut q, HCI_OP_RESET);
    q.dequeue(0);
    q.on_event(HCI_OP_RESET, 1, 10);
    assert_eq!(q.credits(), 1);
    q.on_event(HCI_OP_RESET, 1, 11);
    assert_eq!(q.credits(), 1);
}

#[test]
fn a_completion_clears_the_in_flight_slot() {
    let mut q = CmdQueue::new();
    queued(&mut q, HCI_OP_RESET);
    q.dequeue(0);
    assert_eq!(q.in_flight(), Some(HCI_OP_RESET));
    q.on_event(HCI_OP_RESET, 1, 5);
    assert_eq!(q.in_flight(), None);
}

// A completion naming a different command does not release the one in flight —
// the host is still waiting for it.
#[test]
fn a_completion_for_another_opcode_leaves_the_in_flight_command_alone() {
    let mut q = CmdQueue::new();
    queued(&mut q, HCI_OP_RESET);
    q.dequeue(0);
    q.on_event(HCI_OP_READ_BD_ADDR, 1, 5);
    assert_eq!(q.in_flight(), Some(HCI_OP_RESET));
}

// The no-op opcode is the controller granting a credit while answering nothing.
#[test]
fn a_credit_grant_answering_no_command_restores_the_credit_only() {
    let mut q = CmdQueue::new();
    queued(&mut q, HCI_OP_RESET);
    q.dequeue(0);
    q.on_event(crate::uapi::hci_cmd::HCI_OP_NOP, 1, 5);
    assert_eq!(q.in_flight(), Some(HCI_OP_RESET));
    assert_eq!(q.credits(), 1);
}

#[test]
fn a_command_that_draws_no_completion_expires_naming_its_opcode() {
    let mut q = CmdQueue::new();
    queued(&mut q, HCI_OP_RESET);
    q.dequeue(0);
    assert_eq!(q.expired(crate::uapi::hci::HCI_CMD_TIMEOUT_MS - 1), None);
    assert_eq!(q.expired(crate::uapi::hci::HCI_CMD_TIMEOUT_MS),
        Some(Expiry::Command(HCI_OP_RESET)));
}

#[test]
fn a_completion_disarms_the_command_deadline() {
    let mut q = CmdQueue::new();
    queued(&mut q, HCI_OP_RESET);
    q.dequeue(0);
    q.on_event(HCI_OP_RESET, 1, 1);
    assert_eq!(q.expired(1_000_000), None);
}

// A zero allowance means the controller has stopped accepting commands. It arms
// its own deadline, because a controller that never grants another credit has
// wedged and no command timeout will ever fire to say so.
#[test]
fn a_zero_allowance_arms_the_no_credit_deadline() {
    let mut q = CmdQueue::new();
    queued(&mut q, HCI_OP_RESET);
    q.dequeue(0);
    q.on_event(HCI_OP_RESET, 0, 100);
    assert_eq!(q.credits(), 0);
    assert_eq!(q.expired(100 + crate::uapi::hci::HCI_NCMD_TIMEOUT_MS - 1), None);
    assert_eq!(q.expired(100 + crate::uapi::hci::HCI_NCMD_TIMEOUT_MS), Some(Expiry::NoCredit));
}

#[test]
fn a_restored_allowance_disarms_the_no_credit_deadline() {
    let mut q = CmdQueue::new();
    queued(&mut q, HCI_OP_RESET);
    q.dequeue(0);
    q.on_event(HCI_OP_RESET, 0, 100);
    q.on_event(crate::uapi::hci_cmd::HCI_OP_NOP, 1, 200);
    assert_eq!(q.expired(1_000_000), None);
}

// The two deadlines are mutually exclusive by construction: arming the
// no-credit one clears the command one, and re-arming the command one needs a
// credit, which is exactly what disarms the no-credit one. A state with both
// armed would mean the accounting had already gone wrong.
#[test]
fn at_most_one_deadline_is_ever_armed() {
    // Every reachable sequence of send and answer, over a small alphabet.
    for ncmd_a in [0u8, 1] {
        for ncmd_b in [0u8, 1] {
            let mut q = CmdQueue::new();
            for op in [HCI_OP_RESET, HCI_OP_READ_BD_ADDR,
                crate::uapi::hci_cmd::HCI_OP_READ_LOCAL_VERSION] {
                queued(&mut q, op);
            }
            let mut now = 0;
            for ncmd in [ncmd_a, ncmd_b] {
                if let Some(c) = q.dequeue(now) {
                    now += 1;
                    q.on_event(c.opcode, ncmd, now);
                    now += 1;
                }
                // A command deadline can only be pending while a command is in
                // flight, and a no-credit deadline only while the allowance is
                // spent; the two never overlap.
                let cmd_pending = q.in_flight().is_some() && q.expired(u64::MAX)
                    == Some(Expiry::Command(q.in_flight().unwrap()));
                let ncmd_pending = q.credits() == 0 && q.in_flight().is_none()
                    && q.expired(u64::MAX) == Some(Expiry::NoCredit);
                assert!(!(cmd_pending && ncmd_pending));
            }
        }
    }
}

// A reset clears the controller's command state, so neither deadline is
// meaningful while one is in flight.
#[test]
fn a_controller_being_reset_arms_no_deadline() {
    let mut q = CmdQueue::new();
    q.set_resetting(true);
    queued(&mut q, HCI_OP_RESET);
    q.dequeue(0);
    assert_eq!(q.expired(1_000_000), None);
    q.on_event(HCI_OP_RESET, 0, 0);
    assert_eq!(q.expired(1_000_000), None);
}

#[test]
fn a_flush_drops_every_queued_command_and_restores_the_credit() {
    let mut q = CmdQueue::new();
    queued(&mut q, HCI_OP_RESET);
    queued(&mut q, HCI_OP_READ_BD_ADDR);
    q.dequeue(0);
    q.flush();
    assert_eq!((q.pending(), q.credits(), q.in_flight()), (0, 1, None));
    assert_eq!(q.expired(1_000_000), None);
}

// Ordering is the whole point: the setup sequence depends on each command being
// answered before the next is sent.
#[test]
fn commands_leave_in_the_order_they_were_queued() {
    let mut q = CmdQueue::new();
    for op in [HCI_OP_RESET, HCI_OP_READ_BD_ADDR, crate::uapi::hci_cmd::HCI_OP_READ_LOCAL_VERSION] {
        queued(&mut q, op);
    }
    let mut seen = alloc::vec::Vec::new();
    for step in 0..3u64 {
        let c = q.dequeue(step).unwrap();
        seen.push(c.opcode);
        q.on_event(c.opcode, 1, step);
    }
    assert_eq!(seen, alloc::vec![HCI_OP_RESET, HCI_OP_READ_BD_ADDR,
        crate::uapi::hci_cmd::HCI_OP_READ_LOCAL_VERSION]);
}
