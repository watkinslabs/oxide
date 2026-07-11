use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{EpollData, EPOLL_DATA_OFF, EPOLL_EVENT_SIZE, EPOLLET, GLOBAL_EPOLL_GEN};
use crate::userbuf::validate_user_buf_writable;

/// One non-blocking scan over an epoll's interest list. Writes ready events. # C: O(N_entries)
pub(super) fn scan_once(ep: &Arc<EpollData>, fdt: &Arc<vfs::FdTable>, evp: u64, maxevents: i32) -> i32 {
    let mut reports: Vec<(u32, u64)> = Vec::new();
    {
        let mut list = ep.entries.lock();
        for e in list.iter_mut() {
            if reports.len() as i32 >= maxevents { break; }
            let f = match fdt.get(e.fd) { Ok(f) => f, Err(_) => continue };
            let raw_poll = f.poll();
            let ready = raw_poll & e.events;
            #[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
            if (f.inode().ino() & 0xffff_ffff_0000_0000) == 0x534f_434b_0000_0000 && (raw_poll & 0x1) != 0 {
                let is_db = sched::current().and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| s.contains("dbus-broker")) }).unwrap_or(false);
                if is_db {
                    klog::write_raw(b"[LSCAN fd="); klog::write_dec_u64(e.fd as u64);
                    klog::write_raw(b" raw="); klog::write_hex_u64(raw_poll as u64);
                    klog::write_raw(b" ev="); klog::write_hex_u64(e.events as u64);
                    klog::write_raw(b" rdy="); klog::write_hex_u64(ready as u64);
                    klog::write_raw(b" seen="); klog::write_hex_u64(e.et_seen as u64);
                    klog::write_raw(b"]\n");
                }
            }
            if e.events & EPOLLET != 0 {
                let cur_gen = f.inode().poll_subscribers().map(|s| s.generation()).unwrap_or(e.last_gen);
                let cur_ggen = GLOBAL_EPOLL_GEN.load(Ordering::Acquire);
                let gen_edge = (cur_gen != e.last_gen || cur_ggen != e.last_ggen) && ready != 0;
                e.last_gen = cur_gen;
                e.last_ggen = cur_ggen;
                e.et_seen &= ready;
                let new_edges = ready & !e.et_seen;
                if new_edges == 0 && !gen_edge { continue; }
                e.et_seen |= ready;
            } else if ready == 0 {
                continue;
            } else {
                #[cfg(feature = "debug-epoll")]
                {
                    let n = super::EPOLL_DIAG_N.fetch_add(1, Ordering::Relaxed);
                    if n < 200 {
                        klog::write_raw(b"[epoll-lvl] fd=");
                        klog::write_dec_u64(e.fd as u64);
                        klog::write_raw(b" type=");
                        klog::write_dec_u64(f.inode().file_type() as u64);
                        klog::write_raw(b" poll=");
                        klog::write_hex_u64(f.inode().poll() as u64);
                        klog::write_raw(b" want=");
                        klog::write_hex_u64(e.events as u64);
                        klog::write_raw(b" name=");
                        klog::write_raw(f.dentry().name().as_bytes());
                        klog::write_raw(b"\n");
                    }
                }
            }
            reports.push((ready, e.data));
        }
    }
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
