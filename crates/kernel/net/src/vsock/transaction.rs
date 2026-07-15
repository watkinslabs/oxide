use alloc::vec::Vec;

use super::{send_credit_update, tx_for, VsockConn, VsockState, VIRTIO_VSOCK_OP_RESPONSE};

/// Outcome of a transactional VSOCK stream receive. # C: O(1)
pub enum RecvWith<R> { Data(R), Eof, Retry }

/// Send the server response only while the child remains live. Holding `st`
/// orders response transmission before any listener-close terminal frames.
/// # C: O(1)
pub(super) fn send_accept_response(c: &VsockConn) -> bool {
    let st = c.st.lock();
    if *st == VsockState::Closed { return false; }
    let resp = c.make_hdr(VIRTIO_VSOCK_OP_RESPONSE, 0, 0);
    tx_for(c.owner, &resp, &[])
}

/// Copy one RX prefix under its queue lock and consume only on callback success. # C: O(max)
pub fn recv_with<R, E>(c: &VsockConn, max: usize, peek: bool, copy: impl FnOnce(&[u8]) -> Result<(R, usize), E>)
    -> Result<RecvWith<R>, E>
{ recv_with_offset(c, max, peek, 0, copy) }

/// Copy an RX range after a non-consuming logical offset. # C: O(offset + max)
pub fn recv_with_offset<R, E>(c: &VsockConn, max: usize, peek: bool, offset: usize, copy: impl FnOnce(&[u8]) -> Result<(R, usize), E>)
    -> Result<RecvWith<R>, E>
{
    let mut rx = c.rx.lock();
    if offset >= rx.len() {
        drop(rx);
        let st = c.st.lock();
        rx = c.rx.lock();
        if offset >= rx.len() {
            let eof = matches!(*st, VsockState::RcvShutdown | VsockState::Closed);
            return Ok(if eof { RecvWith::Eof } else { RecvWith::Retry });
        }
        drop(st);
    }
    let take = core::cmp::min(max, rx.len() - offset);
    let bytes: Vec<u8> = rx.iter().skip(offset).take(take).copied().collect();
    let (copied, commit) = copy(&bytes)?;
    if peek { return Ok(RecvWith::Data(copied)); }
    let commit = core::cmp::min(commit, take);
    for _ in 0..commit { rx.pop_front(); }
    drop(rx);
    if commit != 0 {
        let mut cr = c.credit.lock();
        cr.fwd_cnt = cr.fwd_cnt.wrapping_add(commit as u32);
        drop(cr);
        send_credit_update(c);
    }
    Ok(RecvWith::Data(copied))
}
