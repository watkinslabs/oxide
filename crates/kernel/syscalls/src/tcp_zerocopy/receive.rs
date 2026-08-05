// `TCP_ZEROCOPY_RECEIVE` copy-in / remap / copy-out. Every decision — the
// operand layout, the length admission, the errno ordering, the plan, and the
// output-field rules — belongs to `net::sock_opts::sol_tcp::zerocopy`; this
// file moves bytes and drives the address space (`docs/53§4`).
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use net::sock::{InetSocket, SockKind};
use net::sock_opts::sol_tcp::zerocopy as zc;
use net::stack::TcpEntry;

use super::window::window_of;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

const PAGE: u64 = hal::PAGE_SIZE_BYTES;

/// `getsockopt(fd, IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, ...)`.
/// # C: O(mapped bytes)
pub fn get(sock: &Arc<InetSocket>, optval: u64, optlen_p: u64) -> i64 {
    let mut raw_len = [0u8; 4];
    if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() { return errno(Errno::Efault); }
    let len = match zc::admit_optlen(i32::from_ne_bytes(raw_len)) {
        Ok(zc::LenPlan::Use(len)) => len,
        Ok(zc::LenPlan::Clamp { tail_off, tail_len }) => {
            let tail = match optval.checked_add(tail_off as u64) {
                Some(a) => a, None => return errno(Errno::Efault),
            };
            match tail_is_zero(tail, tail_len) {
                Err(e) => return errno(e),
                Ok(false) => return errno(Errno::Einval),
                Ok(true) => {}
            }
            if uaccess::copy_to_user(optlen_p, &(zc::ZC_SIZE as u32).to_ne_bytes()).is_err() {
                return errno(Errno::Efault);
            }
            zc::ZC_SIZE
        }
        Err(e) => return errno(e),
    };
    let mut buf = vec![0u8; len];
    if uaccess::copy_from_user(&mut buf, optval).is_err() { return errno(Errno::Efault); }
    let mut op = zc::Zc::from_bytes(&buf);
    if let Err(e) = zc::validate_input(&op) { return errno(e); }

    // A failed call publishes no operand at all: the caller's struct is only
    // written once bytes have actually moved.
    let timestamp = match run(sock, &mut op) { Ok(timestamp) => timestamp, Err(e) => return errno(e) };

    let stage = zc::output_stage(len);
    if stage >= zc::Stage::Cmsg {
        publish_timestamp(sock, &mut op, timestamp);
    }
    if stage >= zc::Stage::SkErr { op.err = -sock.error.take(); }
    if stage >= zc::Stage::Inq { op.inq = inq(sock) as u32; }
    let bytes = op.to_bytes();
    if uaccess::copy_to_user(optval, &bytes[..len]).is_err() { return errno(Errno::Efault); }
    0
}

/// Whether every byte of the operand tail this kernel does not know is unset.
/// A caller declaring a longer struct is asking for fields this kernel cannot
/// answer unless it set none of them. # C: O(tail bytes)
fn tail_is_zero(addr: u64, len: usize) -> Result<bool, Errno> {
    const CHUNK: usize = 256;
    let mut left = len;
    let mut at = addr;
    let mut probe = [0u8; CHUNK];
    while left != 0 {
        let take = left.min(CHUNK);
        if uaccess::copy_from_user(&mut probe[..take], at).is_err() { return Err(Errno::Efault); }
        if probe[..take].iter().any(|b| *b != 0) { return Ok(false); }
        left -= take;
        at += take as u64;
    }
    Ok(true)
}

/// One mapped receive window resolved from the caller's address.
struct Window {
    backing: Arc<dyn vmm::FileBacking>,
    start: u64,
    end: u64,
}

impl Window {
    /// Publish `pa` at the window offset `va` sits at. # C: O(log N pages)
    fn install(&self, va: u64, pa: u64) -> bool {
        match window_of(&self.backing) {
            Some(w) => { w.install(va - self.start, pa); true }
            None => false,
        }
    }
}

/// Drive one call: plan against the live socket, then execute the plan.
/// # C: O(mapped bytes)
fn run(sock: &Arc<InetSocket>, op: &mut zc::Zc) -> Result<Option<u64>, Errno> {
    let entry = match &*sock.kind.lock() {
        SockKind::TcpConn(entry) => Some(entry.clone()),
        SockKind::TcpListener(_) => None,
        _ => return Err(Errno::Enotconn),
    };
    let listening = entry.is_none();
    let queued = entry.as_ref().map(|e| e.conn.lock().recv_buf.len).unwrap_or(0);
    let done = entry.as_ref().map(|e| {
        sock.read_shut.load(Ordering::Acquire) || net::sock_io::tcp_recv_eof(e.conn.lock().state)
    }).unwrap_or(false);
    let inline = sock.opts.oobinline.load(Ordering::Acquire) != 0;
    let timestamp = entry.as_ref().and_then(|entry| entry.conn.lock().recv_timestamp());
    let window = window_at(op.address);
    let offered = op.copybuf_len;
    let query = zc::ZcQuery {
        address: op.address, length: op.length, copybuf_len: offered, flags: op.flags,
        inq: queued.min(u32::MAX as usize) as u32, listening, done,
        window_end: window.as_ref().map(|w| w.end), page: PAGE,
    };
    let action = zc::plan(&query)?;
    op.copybuf_len = 0;
    op.msg_flags = 0;
    match action {
        zc::ZcAction::Fallback { bytes } => {
            op.length = 0;
            op.recv_skip_hint = 0;
            let entry = entry.ok_or(Errno::Enotconn)?;
            op.copybuf_len = copy_out(&entry, op.copybuf_address, bytes, inline)? as i32;
            Ok((op.copybuf_len != 0).then_some(timestamp).flatten())
        }
        zc::ZcAction::Short { recv_skip_hint } => {
            op.length = 0;
            op.recv_skip_hint = recv_skip_hint;
            Ok(None)
        }
        zc::ZcAction::Map { zap_bytes, map_bytes, length, recv_skip_hint } => {
            let entry = entry.ok_or(Errno::Enotconn)?;
            let window = window.ok_or(Errno::Einval)?;
            // Dropping the window's translations first is what keeps the
            // previous call's pages from being read as this call's bytes.
            if zap_bytes != 0 { pmm::user_as::evict_pages_in_range(op.address, zap_bytes as u64); }
            let mapped = remap(&entry, &window, op.address, map_bytes, inline);
            let want = zc::straggler_bytes(offered, recv_skip_hint);
            let copied = copy_out(&entry, op.copybuf_address, want, inline)?;
            let fin = zc::finish(length, mapped, recv_skip_hint, copied, done)?;
            op.length = fin.length;
            op.recv_skip_hint = fin.recv_skip_hint;
            op.copybuf_len = fin.copybuf_len;
            Ok((mapped != 0 || copied != 0).then_some(timestamp).flatten())
        }
    }
}

/// Publish the timestamp belonging to the first byte this call consumed. The
/// receive queue owns that association; socket options only choose its ABI
/// personality. Ancillary output never undoes stream bytes already consumed.
/// # C: O(1)
fn publish_timestamp(sock: &InetSocket, op: &mut zc::Zc, timestamp: Option<u64>) {
    use net::sock_opts::sol_socket::{self as sol, flag};
    let Some(timestamp) = timestamp else { op.msg_flags = 0; return; };
    sock.note_receive_timestamp(timestamp);
    if !sock.opts.generic.flag(flag::RCVTSTAMP) { op.msg_flags = 0; return; }
    let sec = (timestamp / 1_000_000_000) as i64;
    let subsec = timestamp % 1_000_000_000;
    let nanoseconds = sock.opts.generic.flag(flag::RCVTSTAMPNS);
    let kind = if nanoseconds {
        if sock.opts.generic.flag(flag::TSTAMP_NEW) { sol::SO_TIMESTAMPNS_NEW } else { sol::SO_TIMESTAMPNS_OLD }
    } else if sock.opts.generic.flag(flag::TSTAMP_NEW) { sol::SO_TIMESTAMP_NEW } else { sol::SO_TIMESTAMP_OLD };
    let frac = if nanoseconds { subsec as i64 } else { (subsec / 1_000) as i64 };
    let mut data = [0u8; 16];
    data[..8].copy_from_slice(&sec.to_ne_bytes());
    data[8..].copy_from_slice(&frac.to_ne_bytes());
    let mut control = crate::recv_control::Control::new(op.msg_controllen as usize);
    control.push(sol::SOL_SOCKET as i32, kind as i32, &data);
    let written = control.copy_to_raw(op.msg_control).unwrap_or(0);
    op.msg_control = op.msg_control.saturating_add(written as u64);
    op.msg_controllen = op.msg_controllen.saturating_sub(written as u64);
    op.msg_flags = control.flags;
}

/// Resolve `address` to a receive window in the calling task's address space.
/// A mapping that is not one is no window at all — matching Linux, which
/// accepts only a mapping carrying the transport's own operations table.
/// # C: O(log N_vmas)
fn window_at(address: u64) -> Option<Window> {
    let cur = sched::live::current()?;
    // SAFETY: syscall dispatch context; the running task on this CPU is the sole writer of its own mm slot, so the borrow stays valid for this call.
    let mm = unsafe { cur.mm_ref() }?;
    let vma = mm.find_vma(hal::UserVirtAddr::new(address)?)?;
    let backing = match &vma.backing {
        vmm::VmaBacking::File { backing, .. } => backing.clone(),
        _ => return None,
    };
    window_of(&backing)?;
    Some(Window { backing, start: vma.start.as_u64(), end: vma.end.as_u64() })
}

/// Publish complete page segments from the canonical receive queue at
/// `address`.  The queue transfers its existing object-frame reference to the
/// receive window; no syscall-side receive page is allocated or copied. # C: O(bytes)
fn remap(entry: &Arc<TcpEntry>, w: &Window, address: u64, bytes: u32, inline: bool) -> u32 {
    let mut done = 0u32;
    while done < bytes {
        let pa = match entry.conn.lock().take_zerocopy_page(inline) { Some(pa) => pa, None => break };
        if !w.install(address + done as u64, pa) {
            pmm::setup::release_object_frame(pa);
            break;
        }
        done += PAGE as u32;
    }
    done
}

/// Move `bytes` of the receive queue into the caller's copy buffer.
/// # C: O(bytes)
fn copy_out(entry: &Arc<TcpEntry>, addr: u64, bytes: u32, inline: bool) -> Result<u32, Errno> {
    if bytes == 0 { return Ok(0); }
    let r = net::sock::stack().tcp_recv_with_offset_oob::<usize, Errno>(
        entry, bytes as usize, false, 0, inline,
        |src| {
            if uaccess::copy_to_user(addr, src).is_err() { return Err(Errno::Efault); }
            Ok((src.len(), src.len()))
        });
    Ok(r?.unwrap_or(0) as u32)
}

/// The unread-byte report the operand publishes — the same count the receive
/// path's own report is built from, so the two can never disagree. # C: O(1)
fn inq(sock: &Arc<InetSocket>) -> i32 {
    let entry = match &*sock.kind.lock() {
        SockKind::TcpConn(entry) => entry.clone(),
        _ => return 0,
    };
    let queued = entry.conn.lock().recv_buf.len;
    let eof = sock.read_shut.load(Ordering::Acquire)
        || net::sock_io::tcp_recv_eof(entry.conn.lock().state);
    net::sock_opts::inq::tcp_inq(queued, eof)
}
