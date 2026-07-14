use alloc::vec::Vec;

use super::{send_credit_update, VsockConn, VsockState};

/// Outcome of a transactional VSOCK stream receive. # C: O(1)
pub enum RecvWith<R> { Data(R), Eof, Retry }

/// Copy one RX prefix under its queue lock and consume only on callback success. # C: O(max)
pub fn recv_with<R, E>(c: &VsockConn, max: usize, peek: bool, copy: impl FnOnce(&[u8]) -> Result<(R, usize), E>)
    -> Result<RecvWith<R>, E>
{
    let mut rx = c.rx.lock();
    if rx.is_empty() {
        let eof = matches!(*c.st.lock(), VsockState::RcvShutdown | VsockState::Closed);
        return Ok(if eof { RecvWith::Eof } else { RecvWith::Retry });
    }
    let take = core::cmp::min(max, rx.len());
    let bytes: Vec<u8> = rx.iter().take(take).copied().collect();
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
