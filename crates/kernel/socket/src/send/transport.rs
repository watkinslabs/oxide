use super::*;


#[cfg(target_os = "oxide-kernel")]
fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Mark the stream's last byte urgent once its in-band body is through. A send
/// with no urgent tail returns its byte count untouched.
///
/// `#[inline(never)]`: the urgent path is one branch of one family's send and
/// its frame must not ride under every other protocol's call.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
#[inline(never)]
fn tcp_urgent_tail(ctx: &SendContext<'_>, socket: &Arc<net::sock::InetSocket>,
    message: &Message, total: usize, signals_pipe: bool, flags: u32) -> KResult<usize>
{
    let byte = match crate::oob::tcp_oob_plan(flags as u64 & net::uapi::MSG_OOB != 0,
        message.payload.len())
    {
        crate::oob::OobPlan::Split { .. } => *message.payload.last().ok_or(Error::Einval)?,
        _ => return Ok(total),
    };
    let entry = match &*socket.kind.lock() {
        net::sock::SockKind::TcpConn(entry) => entry.clone(),
        _ => return Err(Error::Einval),
    };
    match net::sock::stack().tcp_send_urgent(&entry, byte) {
        Ok(n) => { net::sock::drain_loopback(); Ok(total.saturating_add(n)) },
        Err(error) => {
            if total != 0 { return Ok(total); }
            let result = Err(Error::from(error));
            if signals_pipe { complete(ctx, flags, result) } else { result }
        }
    }
}

/// `#[inline(never)]`: this is one protocol family's send working set, and
/// `send_prepared` dispatches every family through the same frame (Linux
/// `noinline_for_stack`).
#[cfg(target_os = "oxide-kernel")]
#[inline(never)]
pub(super) fn send_inet(ctx: &SendContext<'_>, target: &SendFile, socket: &Arc<net::sock::InetSocket>,
    message: &Message, flags: u32, prepared: Box<InetPrepared>) -> KResult<usize>
{
    let (dest, control, autobind) = match *prepared {
        InetPrepared::Packet =>
            return crate::packet::send(socket, &message.payload, message.name.as_deref()),
        InetPrepared::Unix(scm) =>
            return send_unix_prepared(ctx, target, socket, message, flags, scm),
        InetPrepared::Transport(address, control, autobind) =>
            (address.remote(), control, autobind),
    };
    let nonblock = target.nonblock() || flags as u64 & net::uapi::MSG_DONTWAIT != 0;
    let signals_pipe = match &*socket.kind.lock() {
        net::sock::SockKind::Unix(_, _) | net::sock::SockKind::TcpConn(_) => true,
        net::sock::SockKind::UnixMsgPair(pair, _) => pair.kind == net::UnixMsgKind::SeqPacket,
        _ => false,
    };
    let deadline = {
        let timeout = socket.opts.base.sndtimeo_ns.load(Ordering::Acquire);
        if timeout > 0 { monotonic_ns().saturating_add(timeout as u64) } else { 0 }
    };
    // One call that both opens the connection and sends: the write reports
    // one result for both halves, so it cannot go through the send loop
    // below, which assumes a connection already exists.
    if net::sock::send_fastopen::opens_connection(socket,
        flags as u64 & net::uapi::MSG_FASTOPEN != 0)
    {
        let result = net::sock::send_fastopen::send(socket, &message.payload, dest, nonblock)
            .map_err(Error::from);
        return if signals_pipe { complete(ctx, flags, result) } else { result };
    }
    let stream = matches!(&*socket.kind.lock(), net::sock::SockKind::TcpConn(_));
    // The urgent pointer is set just past the last byte written, so an
    // out-of-band stream send puts every byte but the last through the
    // ordinary path and marks that one. A zero-length one has nothing to mark
    // and reports zero; it is not refused.
    let plan = if stream { crate::oob::tcp_oob_plan(flags as u64 & net::uapi::MSG_OOB != 0,
        message.payload.len()) } else { crate::oob::OobPlan::Inband };
    if plan == crate::oob::OobPlan::Unsupported { return Ok(0); }
    let body = crate::oob::plan_body(plan, message.payload.len());
    if stream && body == 0 && matches!(plan, crate::oob::OobPlan::Split { .. }) {
        return tcp_urgent_tail(ctx, socket, message, 0, signals_pipe, flags);
    }
    let mut total = 0usize;
    loop {
        let end = if stream { body } else { message.payload.len() };
        match net::sock::sendto(socket, &message.payload[total..end], dest.clone(), ctx.creds(),
            &control, autobind.as_ref())
        {
            Ok(bytes) if stream && bytes != 0 => {
                total += bytes;
                if total >= body {
                    return tcp_urgent_tail(ctx, socket, message, total, signals_pipe, flags);
                }
            }
            Ok(bytes) => return Ok(total.saturating_add(bytes)),
            Err(net::NetError::Eagain) if nonblock => {
                return if total != 0 { Ok(total) } else { Err(Error::Eagain) };
            }
            Err(net::NetError::Eagain) => {
                // Linux `sk_stream_wait_memory` -> `sock_intr_errno(*timeo)`;
                // a partial transfer reports its count, as `do_error:` does.
                if sched::live::interruptible_work_pending_self() {
                    return if total != 0 { Ok(total) }
                        else { Err(Error::from(net::sock_intr::sock_intr_net(deadline))) };
                }
                if deadline != 0 && monotonic_ns() >= deadline {
                    return if total != 0 { Ok(total) } else { Err(Error::Eagain) };
                }
                if !net::sock::wait_transmit(socket, deadline) {
                    return if total != 0 { Ok(total) } else { Err(Error::Eagain) };
                }
            }
            Err(error) => {
                if total != 0 { return Ok(total); }
                let result = Err(Error::from(error));
                return if signals_pipe { complete(ctx, flags, result) } else { result };
            }
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
#[inline(never)]
fn send_unix_prepared(ctx: &SendContext<'_>, target: &SendFile,
    socket: &Arc<net::sock::InetSocket>, message: &Message, flags: u32,
    scm: Box<crate::control::UnixScm>) -> KResult<usize>
{
    send_unix_blocking(ctx, target, socket, message, flags, *scm)
}

#[cfg(target_os = "oxide-kernel")]
fn send_unix_blocking(ctx: &SendContext<'_>, target: &SendFile,
    socket: &Arc<net::sock::InetSocket>, message: &Message, flags: u32,
    scm: crate::control::UnixScm) -> KResult<usize>
{
    let nonblock = target.nonblock() || flags as u64 & net::uapi::MSG_DONTWAIT != 0;
    let timeout = socket.opts.base.sndtimeo_ns.load(Ordering::Acquire);
    let deadline = if timeout > 0 { monotonic_ns().saturating_add(timeout as u64) } else { 0 };
    let cap = socket.opts.base.sndbuf.load(Ordering::Acquire).max(net::sock::TCP_SNDBUF_DEFAULT) as usize;
    // Linux dispatches through the selected socket operation. Keep the
    // equivalent stream classification from one state snapshot instead of
    // taking two more kind locks before the first transmit attempt.
    let (stream, seqpacket) = match &*socket.kind.lock() {
        net::sock::SockKind::Unix(_, _) => (true, false),
        net::sock::SockKind::UnixMsgPair(pair, _)
            if pair.kind == net::UnixMsgKind::SeqPacket => (false, true),
        _ => (false, false),
    };
    // The out-of-band byte is the payload's last: the ordinary loop stops one
    // short of it, then one more pass queues it as the urgent record. Its
    // count is part of the return, so a `MSG_OOB` send reports every byte it
    // was given.
    let plan = crate::oob::unix_oob_plan(stream, flags as u64 & net::uapi::MSG_OOB != 0,
        message.requested_len);
    let body = crate::oob::plan_body(plan, message.payload.len());
    let requested = if matches!(plan, crate::oob::OobPlan::Split { .. }) { body + 1 } else { body };
    let mut total = 0usize;
    loop {
        let tail = crate::oob::owes_oob(plan, total);
        match crate::control::send_unix_once(ctx, socket, message, &scm, cap, total, body, tail) {
            Ok(n) if stream && n != 0 => {
                total += n;
                if total >= requested { return Ok(total); }
            }
            Ok(n) => return Ok(total.saturating_add(n)),
            Err(Error::Eagain) if nonblock => return if total == 0 { Err(Error::Eagain) } else { Ok(total) },
            Err(Error::Eagain) => {
                // Linux `unix_dgram_sendmsg`/`unix_stream_sendmsg`:
                // `sock_intr_errno(timeo)`.
                if sched::live::interruptible_work_pending_self() {
                    return if total == 0 {
                        Err(Error::from(net::sock_intr::sock_intr_net(deadline)))
                    } else { Ok(total) };
                }
                if deadline != 0 && monotonic_ns() >= deadline {
                    return if total == 0 { Err(Error::Eagain) } else { Ok(total) };
                }
                if let Err(error) = crate::control::wait_unix_send(socket, &scm,
                    message.payload.len().saturating_sub(total), cap, deadline)
                {
                    if total != 0 { return Ok(total); }
                    return if error == Error::Epipe
                        && crate::oob::signals_pipe(stream, seqpacket, false) {
                        complete(ctx, flags, Err(error))
                    } else { Err(error) };
                }
            }
            Err(error) => {
                if total != 0 { return Ok(total); }
                // The out-of-band tail is the one stream send that reports
                // EPIPE without raising SIGPIPE: the in-band body owns that
                // signal, and this pass sent no in-band byte.
                return if error == Error::Epipe
                    && crate::oob::signals_pipe(stream, seqpacket, tail)
                { complete(ctx, flags, Err(error)) } else { Err(error) };
            }
        }
    }
}
