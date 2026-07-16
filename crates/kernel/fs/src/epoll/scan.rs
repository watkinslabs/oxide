use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{EpItem, EpollData, EPOLL_DATA_OFF, EPOLL_EVENT_SIZE, EPOLLET, EPOLLONESHOT};
use crate::userbuf::validate_user_buf_writable;

/// Drain one snapshot of the ready list. Source callbacks arriving during the
/// drain stay queued for the next call; level items are requeued after this
/// batch so one item is never reported twice in one wait. # C: O(N_ready)
pub(super) fn scan_once(ep: &Arc<EpollData>, evp: u64, maxevents: i32) -> i32 {
    let mut reports: Vec<(u32, u64)> = Vec::new();
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
            if (f.inode().ino() & net::sock::INET_INO_TAG_MASK) == net::sock::INET_INO_TAG && (raw_poll & 0x1) != 0 {
                let is_db = sched::current().and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| s.contains("dbus-broker")) }).unwrap_or(false);
                if is_db {
                    klog::write_raw(b"[LSCAN fd="); klog::write_dec_u64(item.fd as u64);
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
        reports.push((ready, data));
    }
    for item in requeue { EpItem::queue(&item, true); }
    let mut out = 0i32;
    for (revents, data) in reports.iter() {
        let dst = evp + (out as u64) * (EPOLL_EVENT_SIZE as u64);
        // SAFETY: caller validated writable output span for maxevents epoll_event records.
        unsafe {
            core::ptr::write_unaligned(dst as *mut u32, *revents);
            core::ptr::write_unaligned((dst + EPOLL_DATA_OFF as u64) as *mut u64, *data);
        }
        out += 1;
    }
    out
}

/// Validate the full epoll_wait output array before scanning. # C: O(N_pages)
pub(super) fn validate_events_out(evp: u64, maxevents: i32) -> Result<(), i64> {
    let event_bytes = (maxevents as u64).saturating_mul(EPOLL_EVENT_SIZE as u64);
    validate_user_buf_writable(evp, event_bytes, 1)
}
