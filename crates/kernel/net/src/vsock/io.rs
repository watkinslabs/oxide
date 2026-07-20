//! VSOCK stream and record data-plane ownership.

use super::*;

const NO_RW_FLAGS: u32 = 0;

fn send_admission(c: &VsockConn, tx: &TxState) -> Result<(), NetError> {
    if tx.shut() { return Err(NetError::Epipe); }
    match *c.st.lock() {
        VsockState::Connected | VsockState::RcvShutdown => Ok(()),
        VsockState::Connecting | VsockState::Closed => Err(NetError::Enotconn),
    }
}

/// Send one stream prefix over OP_RW. # C: O(frame)
pub fn send(c: &VsockConn, buf: &[u8]) -> Result<usize, NetError> {
    let _emit = lock_emission(c);
    let mut tx = c.tx.lock();
    send_admission(c, &tx)?;
    let frame_limit = tx_payload_limit(c.owner).ok_or(NetError::Enotconn)?;
    let avail = tx.credit.peer_credit() as usize;
    if avail == 0 { return Err(NetError::Eagain); }
    let sent = buf.len().min(avail).min(frame_limit);
    let header = c.make_hdr_with_credit(&tx.credit, VIRTIO_VSOCK_OP_RW, sent as u32, NO_RW_FLAGS);
    tx.credit.tx_cnt = tx.credit.tx_cnt.wrapping_add(sent as u32);
    drop(tx);
    if tx_for(c.owner, &header, &buf[..sent]) { return Ok(sent); }
    let mut tx = c.tx.lock();
    tx.credit.tx_cnt = tx.credit.tx_cnt.wrapping_sub(sent as u32);
    Err(NetError::Eio)
}

/// Send exactly one complete `SOCK_SEQPACKET` record. The complete record is
/// admitted against the peer and local buffer limits before its first frame;
/// success therefore never reports a partial record. # C: O(record)
pub fn send_seqpacket(c: &VsockConn, buf: &[u8], end_of_record: bool) -> Result<usize, NetError> {
    let _emit = lock_emission(c);
    let mut tx = c.tx.lock();
    send_admission(c, &tx)?;
    let record_limit = core::cmp::min(tx.credit.peer_buf_alloc, tx.credit.buf_alloc) as usize;
    if buf.len() > record_limit { return Err(NetError::Emsgsize); }
    if !buf.is_empty() && tx.credit.peer_credit() as usize < buf.len() {
        return Err(NetError::Eagain);
    }
    let credit = tx.credit;
    tx.credit.tx_cnt = tx.credit.tx_cnt.wrapping_add(buf.len() as u32);
    drop(tx);

    let mut sent = 0usize;
    let frame_limit = tx_payload_limit(c.owner).ok_or(NetError::Enotconn)?;
    loop {
        let remaining = buf.len() - sent;
        let frame_len = remaining.min(frame_limit);
        let final_frame = frame_len == remaining;
        let mut flags = if final_frame { VIRTIO_VSOCK_SEQ_EOM } else { NO_RW_FLAGS };
        if final_frame && end_of_record { flags |= VIRTIO_VSOCK_SEQ_EOR; }
        let header = c.make_hdr_with_credit(&credit, VIRTIO_VSOCK_OP_RW, frame_len as u32, flags);
        if !tx_for(c.owner, &header, &buf[sent..sent + frame_len]) {
            abort_record_emit(c, sent, buf.len());
            return Err(NetError::Eio);
        }
        sent += frame_len;
        if final_frame { return Ok(sent); }
    }
}

/// Abort a failed multi-frame record. Once any fragment was emitted, a reset
/// is the only truthful state: the peer must discard its hidden partial record.
/// # C: O(1)
fn abort_record_emit(c: &VsockConn, sent: usize, record_len: usize) {
    let header = {
        let mut tx = c.tx.lock();
        if sent == 0 {
            tx.credit.tx_cnt = tx.credit.tx_cnt.wrapping_sub(record_len as u32);
            return;
        }
        tx.local_shut = true;
        *c.st.lock() = VsockState::Closed;
        c.make_hdr_with_credit(&tx.credit, VIRTIO_VSOCK_OP_RST, 0, NO_RW_FLAGS)
    };
    TABLE.remove_conn(c);
    let _ = tx_for(c.owner, &header, &[]);
    c.notify_poll(vfs::POLL_IN | vfs::POLL_HUP | vfs::POLL_RDHUP);
    #[cfg(target_os = "oxide-kernel")]
    c.waiters.wake_all();
}

/// Deliver up to `buf.len()` buffered stream bytes and retire matching credit.
/// # C: O(min(buf, buffered))
pub fn recv(c: &VsockConn, buf: &mut [u8]) -> Result<usize, NetError> {
    let mut copied = 0usize;
    {
        let mut rx = c.rx.lock();
        while copied < buf.len() {
            match rx.pop_front() {
                Some(byte) => { buf[copied] = byte; copied += 1; }
                None => break,
            }
        }
    }
    if copied != 0 {
        let mut tx = c.tx.lock();
        tx.credit.fwd_cnt = tx.credit.fwd_cnt.wrapping_add(copied as u32);
        drop(tx);
        send_credit_update(c);
        return Ok(copied);
    }
    match *c.st.lock() {
        VsockState::RcvShutdown | VsockState::Closed => Ok(0),
        VsockState::Connecting => Err(NetError::Eagain),
        VsockState::Connected => Err(NetError::Eagain),
    }
}
