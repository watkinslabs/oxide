use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{EpItem, EpollData, EPOLL_DATA_OFF, EPOLL_EVENT_SIZE, EPOLLET, EPOLLONESHOT};
use crate::userbuf::validate_user_buf_writable;

/// Drain one snapshot of the ready list. Source callbacks arriving during the
/// drain stay queued for the next call; level items are requeued after this
/// batch so one item is never reported twice in one wait. # C: O(N_ready)
pub(super) fn scan_once(ep: &Arc<EpollData>, evp: u64, maxevents: i32) -> i64 {
    let mut reports: Vec<(Arc<EpItem>, u32, u64)> = Vec::new();
    let mut requeue: Vec<Arc<EpItem>> = Vec::new();
    let mut remaining = ep.ready.lock().len();
    while remaining != 0 && (reports.len() as i32) < maxevents {
        remaining -= 1;
        let item = {
            let mut ready = ep.ready.lock();
            let Some(item) = ready.pop_front() else { break; };
            item.queued.store(false, Ordering::Release);
            item
        };
        let (events, data, active, armed) = {
            let state = item.state.lock();
            (state.events, state.data, state.active, state.armed)
        };
        if !active || !armed { continue; }
        let Some(f) = item.file.upgrade() else { EpItem::detach(&item); continue; };
        let raw_poll = f.poll();
        let ready = (raw_poll & events) | (raw_poll & (vfs::POLL_ERR | vfs::POLL_HUP));
            #[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
            // Keep this leaf crate independent of `net`: the diagnostic is
            // scoped to the running dbus-broker and reports every readable
            // watched fd, which is exactly the evidence needed here.
            if (raw_poll & vfs::POLL_IN) != 0 {
                let target = sched::current().map(|c| {
                    c.creds.euid.load(Ordering::Acquire) == 1000
                        || c.with_exe_path(|p| p.map(|s| s.contains("dbus-broker")).unwrap_or(false))
                }).unwrap_or(false);
                if target {
                    klog::write_raw(b"[LSCAN tid=");
                    klog::write_dec_u64(sched::current().map(|c| c.tid as u64).unwrap_or(0));
                    klog::write_raw(b" fd="); klog::write_dec_u64(item.fd as u64);
                    klog::write_raw(b" raw="); klog::write_hex_u64(raw_poll as u64);
                    klog::write_raw(b" ev="); klog::write_hex_u64(events as u64);
                    klog::write_raw(b" rdy="); klog::write_hex_u64(ready as u64);
                    klog::write_raw(b"]\n");
                }
            }
        if ready == 0 {
            continue;
        }
        if events & EPOLLONESHOT != 0 {
            item.state.lock().armed = false;
        } else if events & EPOLLET == 0 {
                #[cfg(feature = "debug-epoll")]
                {
                    let n = super::EPOLL_DIAG_N.fetch_add(1, Ordering::Relaxed);
                    if n < 200 {
                        klog::write_raw(b"[epoll-lvl] fd=");
                        klog::write_dec_u64(item.fd as u64);
                        klog::write_raw(b" type=");
                        klog::write_dec_u64(f.inode().file_type() as u64);
                        klog::write_raw(b" poll=");
                        klog::write_hex_u64(f.inode().poll() as u64);
                        klog::write_raw(b" want=");
                        klog::write_hex_u64(events as u64);
                        klog::write_raw(b" name=");
                        klog::write_raw(f.dentry().name().as_bytes());
                        klog::write_raw(b"\n");
                    }
                }
            requeue.push(Arc::clone(&item));
        }
        reports.push((Arc::clone(&item), ready, data));
    }
    for item in requeue { EpItem::queue(&item, true); }
    // `ep_send_events`: each record is copied out one at a time, and a record
    // that will not go out puts its item BACK on the ready list and ends the
    // batch. Already-delivered records are the return value; only a failure on
    // the very first one is EFAULT, because a caller that got events cannot be
    // told the call failed.
    let mut out = 0i64;
    for (i, (item, revents, data)) in reports.iter().enumerate() {
        let dst = evp + (out as u64) * (EPOLL_EVENT_SIZE as u64);
        if uaccess::copy_to_user(dst, &encode_epoll_event(*revents, *data)).is_err() {
            for (undelivered, _, _) in reports[i..].iter() { EpItem::queue(undelivered, false); }
            let _ = item;
            if out == 0 { return -(syscall::errno::Errno::Efault.as_i32() as i64); }
            break;
        }
        out += 1;
    }
    out
}

/// Split a user `struct epoll_event` into `(events, data)`. The struct is
/// PACKED on x86_64 (`data` at +4) and naturally aligned on aarch64 (`data` at
/// +8), which is what `EPOLL_DATA_OFF` carries. # C: O(1)
pub(super) fn decode_epoll_event(raw: &[u8; EPOLL_EVENT_SIZE]) -> (u32, u64) {
    (u32::from_le_bytes(raw[..4].try_into().expect("4 of the record")),
     u64::from_le_bytes(raw[EPOLL_DATA_OFF..EPOLL_DATA_OFF + 8].try_into().expect("8 of the record")))
}

/// Build one user `struct epoll_event`. Any padding between the two fields is
/// zero, so the reply never carries kernel stack out. # C: O(1)
pub(super) fn encode_epoll_event(events: u32, data: u64) -> [u8; EPOLL_EVENT_SIZE] {
    let mut out = [0u8; EPOLL_EVENT_SIZE];
    out[..4].copy_from_slice(&events.to_le_bytes());
    out[EPOLL_DATA_OFF..EPOLL_DATA_OFF + 8].copy_from_slice(&data.to_le_bytes());
    out
}

/// Validate the full epoll_wait output array before scanning. # C: O(N_pages)
pub(super) fn validate_events_out(evp: u64, maxevents: i32) -> Result<(), i64> {
    let event_bytes = (maxevents as u64).saturating_mul(EPOLL_EVENT_SIZE as u64);
    validate_user_buf_writable(evp, event_bytes, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `struct epoll_event` is packed on x86_64 (`data` at +4) and naturally
    /// aligned on aarch64 (`data` at +8). Both records are built and split by
    /// the same pair, so the round trip pins whichever this arch is.
    #[test]
    fn an_event_record_round_trips_through_its_own_layout() {
        let raw = encode_epoll_event(0xdead_beef, 0x0123_4567_89ab_cdef);
        assert_eq!(raw.len(), EPOLL_EVENT_SIZE);
        assert_eq!(decode_epoll_event(&raw), (0xdead_beef, 0x0123_4567_89ab_cdef));
    }

    /// The events word occupies exactly the first four bytes and the data word
    /// exactly eight bytes at `EPOLL_DATA_OFF`; any gap between them is zero,
    /// so a reply never carries kernel stack out.
    #[test]
    fn the_gap_between_the_two_fields_is_zero() {
        let raw = encode_epoll_event(u32::MAX, u64::MAX);
        for i in 4..EPOLL_DATA_OFF { assert_eq!(raw[i], 0, "byte {i}"); }
        assert!(raw[..4].iter().all(|b| *b == 0xff));
        assert!(raw[EPOLL_DATA_OFF..EPOLL_DATA_OFF + 8].iter().all(|b| *b == 0xff));
    }
}
