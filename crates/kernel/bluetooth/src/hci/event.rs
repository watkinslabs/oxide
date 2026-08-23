//! Event decoding and the state each event changes.
//!
//! Decoding and applying are deliberately separate. Decoding is a total
//! function from bytes to a typed event and refuses anything short; applying
//! takes a typed event and mutates controller state. Splitting them means a
//! malformed event can never partially mutate state, which is exactly how a
//! controller that reports a truncated event corrupts a host's connection
//! table.

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::bt::BdAddr;
use crate::uapi::hci::*;
use crate::uapi::hci_evt::*;
use super::conn::{default_addr_type, Conn, PeerId};
use super::dev::HciDevState;

/// A decoded event. Only the events whose payload the core acts on are typed;
/// everything else is `Other`, which still reaches a raw socket and the monitor
/// but changes no state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    CmdComplete { opcode: u16, ncmd: u8, params: Vec<u8> },
    CmdStatus { status: u8, opcode: u16, ncmd: u8 },
    ConnComplete { status: u8, handle: u16, addr: BdAddr, link_type: u8, encrypted: bool },
    ConnRequest { addr: BdAddr, class: [u8; DEV_CLASS_LEN], link_type: u8 },
    DisconnComplete { status: u8, handle: u16, reason: u8 },
    AuthComplete { status: u8, handle: u16 },
    EncryptChange { status: u8, handle: u16, encrypted: bool },
    NumCompPkts { entries: Vec<(u16, u16)> },
    HardwareError { code: u8 },
    LeConnComplete { status: u8, handle: u16, addr_type: u8, addr: BdAddr },
    LeMeta { subevent: u8, params: Vec<u8> },
    Other { code: u8, params: Vec<u8> },
}

fn le16(b: &[u8], off: usize) -> u16 { u16::from_le_bytes([b[off], b[off + 1]]) }

/// Decode one event from its code and payload. A payload shorter than the
/// event's fixed prefix is refused rather than parsed short. # C: O(len)
pub fn decode(code: u8, body: &[u8]) -> Option<Event> {
    Some(match code {
        HCI_EV_CMD_COMPLETE => {
            if body.len() < EV_CMD_COMPLETE_MIN { return None; }
            Event::CmdComplete { ncmd: body[0], opcode: le16(body, 1), params: body[3..].to_vec() }
        }
        HCI_EV_CMD_STATUS => {
            if body.len() < EV_CMD_STATUS_LEN { return None; }
            Event::CmdStatus { status: body[0], ncmd: body[1], opcode: le16(body, 2) }
        }
        HCI_EV_CONN_COMPLETE => {
            if body.len() < EV_CONN_COMPLETE_LEN { return None; }
            Event::ConnComplete {
                status: body[0], handle: le16(body, 1) & HCI_HANDLE_MASK,
                addr: BdAddr::from_wire(body, 3)?, link_type: body[9], encrypted: body[10] != 0,
            }
        }
        HCI_EV_CONN_REQUEST => {
            if body.len() < EV_CONN_REQUEST_LEN { return None; }
            let mut class = [0u8; DEV_CLASS_LEN];
            class.copy_from_slice(&body[6..6 + DEV_CLASS_LEN]);
            Event::ConnRequest { addr: BdAddr::from_wire(body, 0)?, class, link_type: body[9] }
        }
        HCI_EV_DISCONN_COMPLETE => {
            if body.len() < EV_DISCONN_COMPLETE_LEN { return None; }
            Event::DisconnComplete {
                status: body[0], handle: le16(body, 1) & HCI_HANDLE_MASK, reason: body[3],
            }
        }
        HCI_EV_AUTH_COMPLETE => {
            if body.len() < EV_AUTH_COMPLETE_LEN { return None; }
            Event::AuthComplete { status: body[0], handle: le16(body, 1) & HCI_HANDLE_MASK }
        }
        HCI_EV_ENCRYPT_CHANGE => {
            if body.len() < EV_ENCRYPT_CHANGE_LEN { return None; }
            Event::EncryptChange {
                status: body[0], handle: le16(body, 1) & HCI_HANDLE_MASK, encrypted: body[3] != 0,
            }
        }
        HCI_EV_NUM_COMP_PKTS => {
            if body.is_empty() { return None; }
            let count = body[0] as usize;
            // Each entry is a handle word and a count word. A declared entry
            // count larger than the payload holds is a malformed event: trusting
            // it would credit links that were never reported.
            if body.len() < 1 + count * 4 { return None; }
            let entries = (0..count)
                .map(|i| (le16(body, 1 + i * 4) & HCI_HANDLE_MASK, le16(body, 3 + i * 4)))
                .collect();
            Event::NumCompPkts { entries }
        }
        HCI_EV_HARDWARE_ERROR => {
            if body.is_empty() { return None; }
            Event::HardwareError { code: body[0] }
        }
        HCI_EV_LE_META => {
            if body.len() < EV_LE_META_MIN { return None; }
            let (sub, rest) = (body[0], &body[1..]);
            if sub == HCI_EV_LE_CONN_COMPLETE && rest.len() >= EV_LE_CONN_COMPLETE_LEN {
                Event::LeConnComplete {
                    status: rest[0], handle: le16(rest, 1) & HCI_HANDLE_MASK,
                    addr_type: rest[4], addr: BdAddr::from_wire(rest, 5)?,
                }
            } else {
                Event::LeMeta { subevent: sub, params: rest.to_vec() }
            }
        }
        _ => Event::Other { code, params: body.to_vec() },
    })
}

/// What applying an event asks the caller to do next, beyond the state change
/// the apply already made.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Effect {
    /// Nothing further.
    None,
    /// A command completed; its parameters are the caller's to interpret
    /// against the opcode, which is how the setup sequence advances.
    CommandAnswered { opcode: u16, status: u8, params: Vec<u8> },
    /// A link came up.
    LinkUp { handle: u16 },
    /// A link went away and has been removed from the table.
    LinkDown { handle: u16, reason: u8 },
    /// The controller failed and must be taken down.
    ControllerFailed { code: u8 },
}

/// Status byte a command-complete carries, which is its first parameter byte
/// for every command that reports one. A parameterless complete carries no
/// status and is treated as success. # C: O(1)
pub fn complete_status(params: &[u8]) -> u8 {
    match params.first() { Some(&s) => s, None => HCI_SUCCESS }
}

/// Apply a decoded event to controller state. # C: O(n) over the links touched
pub fn apply(state: &mut HciDevState, ev: &Event, now_ms: u64) -> Effect {
    state.stats.evt_rx = state.stats.evt_rx.saturating_add(1);
    match ev {
        Event::CmdComplete { opcode, ncmd, params } => {
            state.cmd.on_event(*opcode, *ncmd, now_ms);
            Effect::CommandAnswered {
                opcode: *opcode, status: complete_status(params),
                params: params.first().map_or_else(Vec::new, |_| params[1..].to_vec()),
            }
        }
        Event::CmdStatus { status, opcode, ncmd } => {
            state.cmd.on_event(*opcode, *ncmd, now_ms);
            Effect::CommandAnswered { opcode: *opcode, status: *status, params: Vec::new() }
        }
        Event::ConnComplete { status, handle, addr, link_type, encrypted } => {
            if *status != HCI_SUCCESS { return Effect::None; }
            let peer = PeerId::new(*addr, default_addr_type(*link_type));
            let mut conn = Conn::new(*handle, peer, *link_type, false);
            conn.encrypted = *encrypted;
            conn.state = crate::uapi::bt::BT_CONNECTED;
            state.l2cap.remove(*handle);
            state.conns.insert(conn);
            Effect::LinkUp { handle: *handle }
        }
        Event::LeConnComplete { status, handle, addr_type, addr } => {
            if *status != HCI_SUCCESS { return Effect::None; }
            let mut conn = Conn::new(*handle, PeerId::new(*addr, *addr_type), LE_LINK, false);
            conn.state = crate::uapi::bt::BT_CONNECTED;
            state.l2cap.remove(*handle);
            state.conns.insert(conn);
            Effect::LinkUp { handle: *handle }
        }
        Event::DisconnComplete { status, handle, reason } => {
            // A failed disconnection leaves the link up: the controller is
            // saying it did NOT tear the link down, and dropping the entry
            // would lose a live link from the table.
            if *status != HCI_SUCCESS { return Effect::None; }
            state.l2cap.remove(*handle);
            state.conns.remove(*handle);
            Effect::LinkDown { handle: *handle, reason: *reason }
        }
        Event::AuthComplete { status, handle } => {
            if let Some(c) = state.conns.by_handle_mut(*handle) {
                c.authenticated = *status == HCI_SUCCESS;
            }
            Effect::None
        }
        Event::EncryptChange { status, handle, encrypted } => {
            if *status == HCI_SUCCESS {
                if let Some(c) = state.conns.by_handle_mut(*handle) {
                    c.encrypted = *encrypted;
                    if !*encrypted { c.enc_key_size = 0; }
                }
            }
            Effect::None
        }
        Event::NumCompPkts { entries } => {
            for (handle, count) in entries {
                if let Some(c) = state.conns.by_handle_mut(*handle) {
                    c.tx_credits = c.tx_credits.saturating_add(*count);
                }
            }
            Effect::None
        }
        Event::HardwareError { code } => Effect::ControllerFailed { code: *code },
        Event::ConnRequest { .. } | Event::LeMeta { .. } | Event::Other { .. } => Effect::None,
    }
}

#[cfg(test)]
#[path = "tests/event.rs"]
mod tests;
