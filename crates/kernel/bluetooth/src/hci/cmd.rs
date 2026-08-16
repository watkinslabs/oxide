//! Command queue and credit accounting.
//!
//! A controller grants the host a command allowance and repeats its current
//! allowance in every command-status and command-complete event. The host holds
//! at most one command in flight: sending spends the credit, a completion
//! restores it to exactly one rather than incrementing it, so a controller that
//! reports the same completion twice cannot inflate the host's allowance and
//! overrun the controller's own command buffer.
//!
//! Two deadlines guard the exchange. A command that draws no completion within
//! the command timeout has lost its credit; an event that reports an allowance
//! of zero arms the no-credit deadline, because a controller that never grants
//! another credit has stopped accepting commands entirely.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::uapi::hci::{HCI_CMD_CREDIT_ONE, HCI_CMD_TIMEOUT_MS, HCI_NCMD_TIMEOUT_MS};
use crate::uapi::hci_cmd::HCI_OP_NOP;

/// One queued command: the opcode and the parameter bytes that follow it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Command {
    pub opcode: u16,
    pub params: Vec<u8>,
}

/// The deadline that expired, as reported by `expired`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Expiry {
    /// The command in flight drew no completion. Its opcode is carried so the
    /// caller can name the command the controller failed to answer.
    Command(u16),
    /// The controller reported a zero allowance and never restored it.
    NoCredit,
}

/// Command queue with its credit and its two deadlines.
pub struct CmdQueue {
    credits: u16,
    queue: VecDeque<Command>,
    in_flight: Option<u16>,
    cmd_deadline: Option<u64>,
    ncmd_deadline: Option<u64>,
    /// While a reset is in flight the controller's reported allowance is not
    /// authoritative — the reset itself clears the controller's command state —
    /// so neither deadline is armed against it.
    resetting: bool,
}

impl Default for CmdQueue {
    fn default() -> Self { Self::new() }
}

impl CmdQueue {
    /// A queue holding the one credit a controller starts with. # C: O(1)
    pub fn new() -> CmdQueue {
        CmdQueue {
            credits: HCI_CMD_CREDIT_ONE, queue: VecDeque::new(), in_flight: None,
            cmd_deadline: None, ncmd_deadline: None, resetting: false,
        }
    }

    /// Current allowance. # C: O(1)
    pub fn credits(&self) -> u16 { self.credits }

    /// Opcode of the command awaiting a completion, if any. # C: O(1)
    pub fn in_flight(&self) -> Option<u16> { self.in_flight }

    /// Number of commands waiting for a credit. # C: O(1)
    pub fn pending(&self) -> usize { self.queue.len() }

    /// Mark the controller as resetting, which suspends both deadlines until the
    /// reset completes. # C: O(1)
    pub fn set_resetting(&mut self, resetting: bool) {
        self.resetting = resetting;
        if resetting { self.cmd_deadline = None; self.ncmd_deadline = None; }
    }

    /// Enqueue a command behind whatever is already waiting. Ordering is the
    /// whole point of the queue: the setup sequence depends on each command
    /// being answered before the next is sent. # C: O(1)
    pub fn enqueue(&mut self, opcode: u16, params: Vec<u8>) {
        self.queue.push_back(Command { opcode, params });
    }

    /// Take the next command if the allowance permits sending one, spending the
    /// credit and arming the command deadline. # C: O(1)
    pub fn dequeue(&mut self, now_ms: u64) -> Option<Command> {
        if self.credits == 0 || self.in_flight.is_some() { return None; }
        let cmd = self.queue.pop_front()?;
        self.credits -= 1;
        self.in_flight = Some(cmd.opcode);
        self.cmd_deadline = if self.resetting { None } else { Some(now_ms + HCI_CMD_TIMEOUT_MS) };
        Some(cmd)
    }

    /// Apply the allowance an event reports and clear the command deadline.
    ///
    /// `opcode` is the command the event answers; the controller reports the
    /// no-op opcode when the event carries only a credit grant and answers no
    /// command, in which case nothing leaves the in-flight slot. # C: O(1)
    pub fn on_event(&mut self, opcode: u16, ncmd: u8, now_ms: u64) {
        if opcode != HCI_OP_NOP && self.in_flight == Some(opcode) { self.in_flight = None; }
        self.cmd_deadline = None;
        if self.resetting { return; }
        if ncmd != 0 {
            self.credits = HCI_CMD_CREDIT_ONE;
            self.ncmd_deadline = None;
        } else {
            self.credits = 0;
            self.ncmd_deadline = Some(now_ms + HCI_NCMD_TIMEOUT_MS);
        }
    }

    /// Whichever deadline `now_ms` has passed, if either.
    ///
    /// At most one is ever armed: arming the no-credit deadline happens only in
    /// `on_event`, which clears the command deadline first, and re-arming the
    /// command deadline needs a credit, which is exactly what disarms the
    /// no-credit one. The ordering here states which would win if that
    /// invariant were ever broken — the command deadline, because a command
    /// still in flight names the failure more precisely than a stalled
    /// allowance does. # C: O(1)
    pub fn expired(&self, now_ms: u64) -> Option<Expiry> {
        if let (Some(deadline), Some(opcode)) = (self.cmd_deadline, self.in_flight) {
            if now_ms >= deadline { return Some(Expiry::Command(opcode)); }
        }
        if let Some(deadline) = self.ncmd_deadline {
            if now_ms >= deadline { return Some(Expiry::NoCredit); }
        }
        None
    }

    /// Abandon the command in flight and its deadline, leaving the queue's
    /// remaining commands to be sent once a credit returns. # C: O(1)
    pub fn abandon_in_flight(&mut self) {
        self.in_flight = None;
        self.cmd_deadline = None;
    }

    /// Drop every queued command and both deadlines, as a controller going down
    /// requires: the commands name a controller state that no longer exists.
    /// # C: O(n)
    pub fn flush(&mut self) {
        self.queue.clear();
        self.in_flight = None;
        self.cmd_deadline = None;
        self.ncmd_deadline = None;
        self.credits = HCI_CMD_CREDIT_ONE;
    }
}

#[cfg(test)]
#[path = "tests/cmd.rs"]
mod tests;
