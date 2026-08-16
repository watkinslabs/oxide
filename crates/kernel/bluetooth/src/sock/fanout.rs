//! Delivering a frame to every socket that should see it.
//!
//! Without this the sockets are machinery with no caller: the receive path
//! would decode a frame, change controller state, and hand it to nobody. Every
//! frame in either direction passes through here on its way to the raw sockets
//! bound to that controller and to every monitor socket, which is what makes a
//! live protocol trace possible.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{HciRegistry as BtSockRegClass, Spinlock};

use crate::hci::mon::{frame_record, Dir};
use crate::uapi::hci_sock::{HCI_CHANNEL_MONITOR, HCI_CHANNEL_RAW, HCI_CHANNEL_USER};
use super::inode::HciSocketFile;

static SOCKETS: Spinlock<Vec<Arc<HciSocketFile>>, BtSockRegClass> = Spinlock::new(Vec::new());

/// Publish a socket so it can receive. # C: O(1)
pub fn register(sock: &Arc<HciSocketFile>) { SOCKETS.lock().push(Arc::clone(sock)); }

/// Withdraw a socket. Returns whether one was withdrawn. # C: O(n)
pub fn unregister(sock: &Arc<HciSocketFile>) -> bool {
    let mut list = SOCKETS.lock();
    match list.iter().position(|s| Arc::ptr_eq(s, sock)) {
        Some(at) => { list.remove(at); true }
        None => false,
    }
}

/// Number of published sockets. # C: O(1)
pub fn count() -> usize { SOCKETS.lock().len() }

/// Deliver one whole H:4 frame from a controller to every socket that should
/// see it.
///
/// A raw socket receives the frame itself, screened by its controller binding
/// and its filter. A monitor socket receives the frame wrapped in a monitor
/// record instead, because that is the format the trace is made of — handing a
/// monitor socket the bare frame would produce a trace one header short.
/// Returns how many sockets received something. # C: O(n * len)
pub fn deliver(index: u16, frame: &[u8], dir: Dir) -> usize {
    let Some((&pkt_type, rest)) = frame.split_first() else { return 0; };
    let head = crate::hci::packet::header_word(pkt_type, rest).unwrap_or(0);
    let record = frame_record(index, frame, dir);
    let list: Vec<Arc<HciSocketFile>> = SOCKETS.lock().clone();
    let mut delivered = 0;
    for sock in list {
        let mut st = sock.state.lock();
        if !st.accepts(index, pkt_type, head) { continue; }
        match st.channel() {
            Some(HCI_CHANNEL_MONITOR) => match record.as_ref() {
                Some(r) => { st.push(r.clone()); delivered += 1; }
                // A packet type with no monitor opcode has no record form, so
                // there is nothing well-formed to hand a monitor socket.
                None => {}
            },
            Some(HCI_CHANNEL_RAW) | Some(HCI_CHANNEL_USER) => {
                st.push(frame.to_vec());
                delivered += 1;
            }
            _ => {}
        }
    }
    delivered
}

#[cfg(test)]
#[path = "tests/fanout.rs"]
mod tests;
