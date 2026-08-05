// Socket-owned TCP timers. Each callback retains and processes one TcpEntry;
// no expiry walks the connection table.

use super::*;
use super::tcp_tx::TcpTxPolicy;
use alloc::boxed::Box;
use ::core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const TIME_WAIT_NS: u64 = 60_000_000_000;

#[derive(Copy, Clone)]
enum TimerKind { Write, DelAck, KeepAlive, Cleanup }

struct TimerSlot {
    id: AtomicU64,
    generation: AtomicU64,
    deadline: AtomicU64,
}

impl TimerSlot {
    const fn new() -> Self {
        Self {
            id: AtomicU64::new(0), generation: AtomicU64::new(0),
            deadline: AtomicU64::new(0),
        }
    }
}

/// Independent timer roles owned by one transport entry.
pub(crate) struct TcpTimers {
    live: AtomicBool,
    write: TimerSlot,
    delack: TimerSlot,
    keepalive: TimerSlot,
    cleanup: TimerSlot,
}

/// Timer ownership and the poll subscriber slot share one allocation, keeping
/// the interrupt-path TcpEntry itself within its stack-size budget.
pub(crate) struct TcpAsyncState {
    timers: TcpTimers,
    subscribers: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
}

impl TcpAsyncState {
    /// # C: O(1)
    pub(crate) const fn new() -> Self {
        Self { timers: TcpTimers::new(), subscribers: Spinlock::new(None) }
    }
}

impl ::core::ops::Deref for TcpAsyncState {
    type Target = Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>;
    fn deref(&self) -> &Self::Target { &self.subscribers }
}

impl TcpTimers {
    /// # C: O(1)
    pub(crate) const fn new() -> Self {
        Self {
            live: AtomicBool::new(false),
            write: TimerSlot::new(), delack: TimerSlot::new(), keepalive: TimerSlot::new(),
            cleanup: TimerSlot::new(),
        }
    }

    fn slot(&self, kind: TimerKind) -> &TimerSlot {
        match kind {
            TimerKind::Write => &self.write,
            TimerKind::DelAck => &self.delack,
            TimerKind::KeepAlive => &self.keepalive,
            TimerKind::Cleanup => &self.cleanup,
        }
    }
}

struct TimerContext {
    entry: Arc<TcpEntry>,
    kind: TimerKind,
    generation: u64,
}

fn drop_context(arg: usize) {
    // SAFETY: `arg` is produced exactly once by Box::into_raw in arm; the
    // owned timer invokes this exactly once after fire or cancellation.
    unsafe { drop(Box::from_raw(arg as *mut TimerContext)); }
}

fn fire_context(arg: usize, id: timer::TimerId) {
    // SAFETY: the owned timer retains this Box for the duration of the call.
    let context = unsafe { &*(arg as *const TimerContext) };
    let timers = &context.entry.poll_subs.timers;
    let slot = timers.slot(context.kind);
    if slot.generation.load(Ordering::Acquire) != context.generation { return; }
    if slot.id.compare_exchange(id.raw(), 0, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return;
    }
    slot.deadline.store(0, Ordering::Release);
    if !timers.live.load(Ordering::Acquire) { return; }
    let now_ns = crate::tcp_conn::ka_now_ns();
    let stack = crate::sock::stack();
    match context.kind {
        TimerKind::Write => stack.fire_tcp_write_timer(&context.entry, now_ns),
        TimerKind::DelAck => stack.fire_tcp_delack_timer(&context.entry, now_ns),
        TimerKind::KeepAlive => stack.fire_tcp_keepalive_timer(&context.entry, now_ns),
        TimerKind::Cleanup => stack.fire_tcp_cleanup_timer(&context.entry, now_ns),
    }
}

fn key(entry: &TcpEntry) -> TcpKey {
    let c = entry.conn.lock();
    TcpKey {
        local_ip: c.local.ip, local_port: c.local.port,
        remote_ip: c.remote.ip, remote_port: c.remote.port,
    }
}

fn cancel_slot(slot: &TimerSlot) {
    slot.generation.fetch_add(1, Ordering::AcqRel);
    slot.deadline.store(0, Ordering::Release);
    if let Some(id) = timer::TimerId::from_raw(slot.id.swap(0, Ordering::AcqRel)) {
        let _ = timer::unregister_oneshot(id);
    }
}

/// Cancel every timer owned by an entry before it leaves demux. # C: O(1)
pub(super) fn cancel(entry: &TcpEntry) {
    entry.poll_subs.timers.live.store(false, Ordering::Release);
    cancel_slot(&entry.poll_subs.timers.write);
    cancel_slot(&entry.poll_subs.timers.delack);
    cancel_slot(&entry.poll_subs.timers.keepalive);
    cancel_slot(&entry.poll_subs.timers.cleanup);
}

fn arm_slot(entry: &Arc<TcpEntry>, kind: TimerKind, deadline: Option<u64>) {
    let slot = entry.poll_subs.timers.slot(kind);
    let target = deadline.map_or(0, |deadline| deadline.max(1));
    if target != 0 && slot.id.load(Ordering::Acquire) != 0
        && slot.deadline.load(Ordering::Acquire) == target
    {
        return;
    }
    let generation = slot.generation.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    slot.deadline.store(0, Ordering::Release);
    if let Some(id) = timer::TimerId::from_raw(slot.id.swap(0, Ordering::AcqRel)) {
        let _ = timer::unregister_oneshot(id);
    }
    if target == 0 { return; }
    if !entry.poll_subs.timers.live.load(Ordering::Acquire) { return; }
    let context = Box::new(TimerContext { entry: entry.clone(), kind, generation });
    let arg = Box::into_raw(context) as usize;
    let id = timer::register_oneshot_owned(target, arg, fire_context, drop_context);
    if slot.generation.load(Ordering::Acquire) != generation
        || !entry.poll_subs.timers.live.load(Ordering::Acquire)
    {
        let _ = timer::unregister_oneshot(id);
        return;
    }
    slot.deadline.store(target, Ordering::Release);
    if slot.id.compare_exchange(0, id.raw(), Ordering::AcqRel, Ordering::Acquire).is_err() {
        let _ = timer::unregister_oneshot(id);
        return;
    }
    if slot.generation.load(Ordering::Acquire) != generation
        || !entry.poll_subs.timers.live.load(Ordering::Acquire)
    {
        if slot.id.compare_exchange(id.raw(), 0, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            slot.deadline.store(0, Ordering::Release);
            let _ = timer::unregister_oneshot(id);
        }
    }
}

fn min_deadline(current: Option<u64>, candidate: u64) -> Option<u64> {
    Some(current.map_or(candidate, |deadline| deadline.min(candidate)))
}

fn deadlines(entry: &TcpEntry, now_ns: u64)
    -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>)
{
    let mut c = entry.conn.lock();
    let mut write = None;
    if c.state == crate::tcp_state::TcpState::SynRecv && c.rsk.armed() {
        write = Some(c.rsk.expires_ns);
    } else if !c.repair {
        for segment in c.retx_q.iter().filter(|segment| !segment.sacked) {
            write = min_deadline(write, segment.last_sent_ns.saturating_add(c.rto_ns));
            if c.state == crate::tcp_state::TcpState::SynSent { break; }
        }
        if c.user_timeout_ns != 0 && c.first_unacked_ns != 0 {
            write = min_deadline(write,
                c.first_unacked_ns.saturating_add(c.user_timeout_ns));
        }
        if !c.send_buf.is_empty() && c.telemetry.pacing_next_ns != 0 {
            write = min_deadline(write, c.telemetry.pacing_next_ns);
        }
    }

    let delack = if c.ack_pending {
        if c.ack_deadline_ns == 0 {
            c.ack_deadline_ns = now_ns.saturating_add(c.delack_ato_ns());
        }
        Some(c.ack_deadline_ns)
    } else { None };

    let cleanup = match c.state {
        crate::tcp_state::TcpState::Closed => Some(now_ns.saturating_add(1)),
        crate::tcp_state::TcpState::TimeWait => {
            if c.tw_start_ns == 0 { c.tw_start_ns = now_ns; }
            Some(c.tw_start_ns.saturating_add(TIME_WAIT_NS))
        }
        crate::tcp_state::TcpState::FinWait2 => {
            if c.tw_start_ns == 0 { c.tw_start_ns = now_ns; }
            Some(c.tw_start_ns.saturating_add(c.linger2_ns))
        }
        _ => None,
    };
    let keepalive = if c.ka_enabled && matches!(c.state,
        crate::tcp_state::TcpState::Established | crate::tcp_state::TcpState::CloseWait)
    {
        Some(if c.ka_count == 0 {
            c.last_rx_ns.saturating_add(c.ka_idle_ns)
        } else { c.next_ka_ns })
    } else { None };
    (write, delack, keepalive, cleanup)
}

impl NetStack {
    /// Hosted compatibility driver for tests written against the former sweep.
    /// Production has no caller or registration for this table walk.
    #[cfg(test)]
    pub(crate) fn tcp_retx_tick(&self, now_ns: u64) {
        for (_, _tables, _key, entry) in self.tcp_tick_entries() {
            self.fire_tcp_write_timer(&entry, now_ns);
            self.fire_tcp_delack_timer(&entry, now_ns);
            self.fire_tcp_keepalive_timer(&entry, now_ns);
            self.fire_tcp_cleanup_timer(&entry, now_ns);
        }
    }

    /// Publish timer ownership after the connection is visible in its table. # C: O(retx_q)
    pub(crate) fn activate_tcp_timers(&self, entry: &Arc<TcpEntry>) {
        entry.poll_subs.timers.live.store(true, Ordering::Release);
        self.refresh_tcp_timers(entry);
    }

    /// Recompute this socket's deadlines after a state or queue change.
    /// # C: O(retx_q)
    pub(crate) fn refresh_tcp_timers(&self, entry: &Arc<TcpEntry>) {
        if !entry.poll_subs.timers.live.load(Ordering::Acquire) { return; }
        let (write, delack, keepalive, cleanup) =
            deadlines(entry, crate::tcp_conn::ka_now_ns());
        arm_slot(entry, TimerKind::Write, write);
        arm_slot(entry, TimerKind::DelAck, delack);
        arm_slot(entry, TimerKind::KeepAlive, keepalive);
        arm_slot(entry, TimerKind::Cleanup, cleanup);
    }

    fn fire_tcp_write_timer(&self, entry: &Arc<TcpEntry>, now_ns: u64) {
        let key = key(entry);
        let tables = self.inet_tables(entry.net_ns());
        if entry.conn.lock().state == crate::tcp_state::TcpState::SynRecv {
            self.tcp_reqsk_timer(&tables, &key, entry, now_ns);
            self.refresh_tcp_timers(entry);
            return;
        }
        let (segments, abort, src, dst) = {
            let mut c = entry.conn.lock();
            if c.repair || c.retx_q.is_empty() {
                (Vec::new(), false, c.local.ip, c.remote.ip)
            } else {
                let front_is_syn = c.retx_q.front().is_some_and(|segment|
                    (segment.flags & crate::tcp_hdr::flags::SYN) != 0);
                let ceiling = if front_is_syn { c.syn_retries }
                    else { crate::tcp_conn::DATA_RETRIES_DEFAULT };
                let retries = c.retx_q.iter().map(|segment| segment.retries).max().unwrap_or(0);
                let abort = retries >= ceiling || c.user_timeout_expired(now_ns);
                if c.fastopen_blackholed(abort) { c.fastopen_blackhole_seen = true; }
                if abort {
                    c.state = crate::tcp_state::TcpState::Closed;
                    c.retx_q.clear();
                    (Vec::new(), true, c.local.ip, c.remote.ip)
                } else {
                    let segments = c.retransmit_due(now_ns);
                    (segments, false, c.local.ip, c.remote.ip)
                }
            }
        };
        super::tcp_fastopen::drain_client(self, entry, now_ns);
        for segment in &segments {
            let _ = self.send_tcp_segment_in(entry.net_ns(), src, dst, segment, 0,
                entry.bound_iface(), TcpTxPolicy::Entry(entry));
        }
        if abort {
            entry.set_error(syscall::errno::Errno::Etimedout as i32);
            entry.release_backlog();
            super::tcp_listener::remove_tcp_entry_exact(&tables, &key, entry);
            #[cfg(target_os = "oxide-kernel")]
            entry.rx_waiters.wake_all();
            return;
        }

        let (paced, pace_src, pace_dst, tos, max_rate) = {
            let mut c = entry.conn.lock();
            let max_rate = entry.max_pacing_rate.load(Ordering::Acquire);
            let active = max_rate != u64::MAX || c.telemetry.pacing_next_ns != 0;
            let paced = if active && c.pacing_ready_at(now_ns, max_rate) {
                c.output_limit(1500, true, false,
                    if max_rate == u64::MAX { usize::MAX } else { 1 })
            } else { Vec::new() };
            (paced, c.local.ip, c.remote.ip, ecn_tos(&c), max_rate)
        };
        for segment in &paced {
            let _ = self.send_tcp_segment_in(entry.net_ns(), pace_src, pace_dst, segment, tos,
                entry.bound_iface(), TcpTxPolicy::Entry(entry));
        }
        if !paced.is_empty() {
            stamp_last_sent(entry, paced.len());
            let bytes = entry.conn.lock().retx_q.back().map_or(0, |segment| segment.payload.len());
            entry.conn.lock().note_paced_output_at(now_ns, bytes, max_rate);
        }
        #[cfg(target_os = "oxide-kernel")]
        if !segments.is_empty() { entry.rx_waiters.wake_all(); }
        self.refresh_tcp_timers(entry);
    }

    fn fire_tcp_delack_timer(&self, entry: &Arc<TcpEntry>, now_ns: u64) {
        let (segment, src, dst) = {
            let mut c = entry.conn.lock();
            (c.delayed_ack_due(now_ns), c.local.ip, c.remote.ip)
        };
        if let Some(segment) = &segment {
            let _ = self.send_tcp_segment_in(entry.net_ns(), src, dst, segment, 0,
                entry.bound_iface(), TcpTxPolicy::Entry(entry));
        }
        self.refresh_tcp_timers(entry);
    }

    fn fire_tcp_keepalive_timer(&self, entry: &Arc<TcpEntry>, now_ns: u64) {
        let key = key(entry);
        let tables = self.inet_tables(entry.net_ns());
        let (segment, exhausted, src, dst) = {
            let mut c = entry.conn.lock();
            let segment = c.keepalive_due(now_ns);
            let exhausted = c.ka_count > c.ka_cnt_max;
            if exhausted { c.state = crate::tcp_state::TcpState::Closed; }
            (segment, exhausted, c.local.ip, c.remote.ip)
        };
        if let Some(segment) = &segment {
            let _ = self.send_tcp_segment_in(entry.net_ns(), src, dst, segment, 0,
                entry.bound_iface(), TcpTxPolicy::Entry(entry));
        }
        if exhausted {
            entry.set_error(syscall::errno::Errno::Etimedout as i32);
            entry.release_backlog();
            super::tcp_listener::remove_tcp_entry_exact(&tables, &key, entry);
            #[cfg(target_os = "oxide-kernel")]
            entry.rx_waiters.wake_all();
            return;
        }
        self.refresh_tcp_timers(entry);
    }

    fn fire_tcp_cleanup_timer(&self, entry: &Arc<TcpEntry>, now_ns: u64) {
        let expired = {
            let mut c = entry.conn.lock();
            let expired = match c.state {
                crate::tcp_state::TcpState::Closed => true,
                crate::tcp_state::TcpState::TimeWait =>
                    now_ns.saturating_sub(c.tw_start_ns) >= TIME_WAIT_NS,
                crate::tcp_state::TcpState::FinWait2 =>
                    c.linger2_expired(c.tw_start_ns, now_ns),
                _ => false,
            };
            if expired { c.state = crate::tcp_state::TcpState::Closed; }
            expired
        };
        if expired {
            let key = key(entry);
            let tables = self.inet_tables(entry.net_ns());
            entry.release_backlog();
            super::tcp_listener::remove_tcp_entry_exact(&tables, &key, entry);
            #[cfg(target_os = "oxide-kernel")]
            entry.rx_waiters.wake_all();
            return;
        }
        self.refresh_tcp_timers(entry);
    }
}
