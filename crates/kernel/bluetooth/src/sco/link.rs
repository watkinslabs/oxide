//! The contract between the SCO layer and the controller.
//!
//! The SCO layer builds commands and voice packets and hands them over; it does
//! not look up controllers, allocate handles or track links. Everything it needs
//! to know about a link arrives as an argument, which is what lets the whole
//! negotiation be exercised without a controller.

use alloc::vec::Vec;
use syscall::errno::Errno;

/// What the SCO layer needs from the controller.
pub trait ScoTx {
    /// Send one command with its already-encoded parameters. # C: O(n)
    fn send_cmd(&mut self, opcode: u16, params: &[u8]) -> Result<(), Errno>;

    /// Send one voice packet on a link. # C: O(n)
    fn send_data(&mut self, handle: u16, payload: &[u8]) -> Result<(), Errno>;
}

/// A collector standing in for the controller, which is what a test drives the
/// negotiation with.
#[derive(Default, Debug)]
pub struct CmdLog {
    pub cmds: Vec<(u16, Vec<u8>)>,
    pub data: Vec<(u16, Vec<u8>)>,
}

impl CmdLog {
    /// An empty log. # C: O(1)
    pub fn new() -> CmdLog { CmdLog { cmds: Vec::new(), data: Vec::new() } }

    /// The last command collected. # C: O(1)
    pub fn last_cmd(&self) -> Option<&(u16, Vec<u8>)> { self.cmds.last() }

    /// Number of commands collected. # C: O(1)
    pub fn len(&self) -> usize { self.cmds.len() }

    /// Whether nothing has been collected. # C: O(1)
    pub fn is_empty(&self) -> bool { self.cmds.is_empty() && self.data.is_empty() }
}

impl ScoTx for CmdLog {
    /// Collect one command. # C: O(n)
    fn send_cmd(&mut self, opcode: u16, params: &[u8]) -> Result<(), Errno> {
        self.cmds.push((opcode, params.to_vec()));
        Ok(())
    }

    /// Collect one voice packet. # C: O(n)
    fn send_data(&mut self, handle: u16, payload: &[u8]) -> Result<(), Errno> {
        self.data.push((handle, payload.to_vec()));
        Ok(())
    }
}
