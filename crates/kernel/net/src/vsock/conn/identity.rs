//! VSOCK connection wire-header and table-key construction.

use crate::vsock::hdr::VsockHdr;
use super::{ConnKey, Credit, VsockConn};

impl VsockConn {
    /// Build a control/data header with the live connection credit. # C: O(1)
    pub fn make_hdr(&self, op: u16, len: u32, flags: u32) -> VsockHdr {
        let tx = self.tx.lock();
        self.make_hdr_with_credit(&tx.credit, op, len, flags)
    }

    /// Build a header while the caller owns the transmit gate. # C: O(1)
    pub fn make_hdr_with_credit(&self, credit: &Credit, op: u16, len: u32, flags: u32) -> VsockHdr {
        VsockHdr {
            src_cid: self.local_cid, dst_cid: self.peer_cid, src_port: self.local_port,
            dst_port: self.peer_port, len, typ: self.transport_type.wire_type(), op, flags,
            buf_alloc: credit.buf_alloc, fwd_cnt: credit.fwd_cnt,
        }
    }

    /// Return this connection's exact owner-qualified table key. # C: O(1)
    pub fn key(&self) -> ConnKey {
        ConnKey { owner: self.owner, local_cid: self.local_cid, local_port: self.local_port,
            peer_cid: self.peer_cid, peer_port: self.peer_port }
    }
}
