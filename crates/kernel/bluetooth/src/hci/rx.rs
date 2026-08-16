//! The receive path: one frame from a transport, all the way into controller
//! state.
//!
//! This is the function that makes the core reachable. A transport driver holds
//! nothing above the frame; it calls here, and everything the frame means —
//! credits, connections, setup progress — happens on this path.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::uapi::hci::{HCI_ACLDATA_PKT, HCI_EVENT_PKT, HCI_ISODATA_PKT, HCI_SCODATA_PKT};
use super::event::{apply, decode, Effect};
use super::packet::parse_frame;
use super::registry::HciDev;

/// What one received frame produced, for the caller to act on above the lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Received {
    /// The frame was malformed and has been dropped.
    Malformed,
    /// An event was applied; this is what it asks for next.
    Event(Effect),
    /// A data frame arrived on a link, for the protocol above to reassemble.
    Data { pkt_type: u8, handle: u16, flags: u16, body: Vec<u8> },
}

/// Take one whole H:4 frame from a transport and apply it.
///
/// The controller's state lock is taken for the apply and released before the
/// effect is returned, so a caller acting on the effect — bringing a link up,
/// sending the next setup command — never does so with the lock held.
/// # C: O(len)
pub fn receive(dev: &Arc<HciDev>, frame: &[u8], now_ms: u64) -> Received {
    // Every frame reaches the sockets watching this controller, malformed ones
    // included: a trace that silently omitted the frame that broke the
    // controller is the trace nobody can debug with.
    crate::sock::fanout::deliver(dev.index, frame, crate::hci::mon::Dir::Rx);
    let Some(parsed) = parse_frame(frame) else {
        let mut st = dev.state.lock();
        st.stats.err_rx = st.stats.err_rx.saturating_add(1);
        return Received::Malformed;
    };
    match parsed.pkt_type {
        HCI_EVENT_PKT => {
            let Some(ev) = decode(parsed.head as u8, &parsed.body) else {
                let mut st = dev.state.lock();
                st.stats.err_rx = st.stats.err_rx.saturating_add(1);
                return Received::Malformed;
            };
            let effect = { let mut st = dev.state.lock(); apply(&mut st, &ev, now_ms) };
            Received::Event(effect)
        }
        HCI_ACLDATA_PKT | HCI_SCODATA_PKT | HCI_ISODATA_PKT => {
            let (handle, flags) = crate::uapi::hci::acl_unpack(parsed.head);
            {
                let mut st = dev.state.lock();
                match parsed.pkt_type {
                    HCI_ACLDATA_PKT => st.stats.acl_rx = st.stats.acl_rx.saturating_add(1),
                    HCI_SCODATA_PKT => st.stats.sco_rx = st.stats.sco_rx.saturating_add(1),
                    _ => {}
                }
                st.stats.byte_rx = st.stats.byte_rx.saturating_add(frame.len() as u32);
            }
            Received::Data { pkt_type: parsed.pkt_type, handle, flags, body: parsed.body }
        }
        // A command travels the other way. A controller sending one is
        // malformed traffic, not a frame to route.
        _ => {
            let mut st = dev.state.lock();
            st.stats.err_rx = st.stats.err_rx.saturating_add(1);
            Received::Malformed
        }
    }
}

/// Send one built frame down a controller's transport, counting it. # C: O(len)
pub fn transmit(dev: &Arc<HciDev>, frame: &[u8]) -> Result<(), syscall::errno::Errno> {
    dev.send(frame)?;
    crate::sock::fanout::deliver(dev.index, frame, crate::hci::mon::Dir::Tx);
    let mut st = dev.state.lock();
    match frame.first().copied() {
        Some(crate::uapi::hci::HCI_COMMAND_PKT) => st.stats.cmd_tx = st.stats.cmd_tx.saturating_add(1),
        Some(HCI_ACLDATA_PKT) => st.stats.acl_tx = st.stats.acl_tx.saturating_add(1),
        Some(HCI_SCODATA_PKT) => st.stats.sco_tx = st.stats.sco_tx.saturating_add(1),
        _ => {}
    }
    st.stats.byte_tx = st.stats.byte_tx.saturating_add(frame.len() as u32);
    Ok(())
}

/// Send whatever the command queue is ready to send, if the allowance permits.
/// Returns the frame sent, so a caller can trace it. # C: O(len)
pub fn pump_commands(dev: &Arc<HciDev>, now_ms: u64) -> Option<Vec<u8>> {
    let cmd = { let mut st = dev.state.lock(); st.cmd.dequeue(now_ms)? };
    let frame = super::packet::build_frame(crate::uapi::hci::HCI_COMMAND_PKT, cmd.opcode, &cmd.params)?;
    match transmit(dev, &frame) {
        Ok(()) => Some(frame),
        // The transport refused the frame, so the command never left. Give the
        // slot back rather than waiting out a deadline for an answer to a
        // command the controller never saw.
        Err(_) => { dev.state.lock().cmd.abandon_in_flight(); None }
    }
}
