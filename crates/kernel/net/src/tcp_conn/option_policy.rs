use alloc::vec::Vec;

use crate::syncookies::Permitted;
use crate::tcp_conn::{TcpConn, TcpConnError};

impl TcpConn {
    /// Apply one segment under the owning namespace's handshake-option policy.
    /// Established connections retain what their handshake already negotiated.
    /// # C: O(segment)
    pub(crate) fn input_prevalidated_with_options(&mut self, src_ip: crate::addr::IpAddr,
        dst_ip: crate::addr::IpAddr, seg: &[u8], permitted: Permitted)
        -> Result<Option<Vec<u8>>, TcpConnError>
    {
        let hdr = crate::tcp_hdr::parse_prevalidated(seg).map_err(|_| TcpConnError::BadHdr)?;
        self.input_completing_request(src_ip, dst_ip, seg, hdr,
            vfs::inode_times::realtime_now_ns(), permitted)
    }
}
