// Linux `__send_signal_locked` / `send_signal_locked` / `force_sig_info_to_task`
// — the ONE way a signal becomes pending in this kernel.
//
// Every producer routes here: `kill(2)`, `tgkill`, `sigqueue`, the arch fault
// classifiers, POSIX timers, tty job control, SIGCHLD, SIGPIPE/SIGXFSZ, the OOM
// killer, cgroup kill, ptrace. Producers that open-coded
// `t.sigpending.fetch_or(bit)` each independently lost the queued `siginfo_t`,
// the private-vs-shared set choice, `prepare_signal`'s SIGCONT/stop flush, and
// sometimes the wake — which is how synchronous fault signals ended up bypassing
// the queue entirely and writing a hand-rolled siginfo onto the user stack.
//
// The DECISIONS are ungated in `crate::sigsend` and hosted-tested there; this
// file is the mechanism (queue push, registry walk, wake) and is kernel-only.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::sigsend::{self, ForceMode, SigSource, SigTarget};
use crate::signum::{self, Signum};
use crate::task::{SigInfo, Task};

/// Why a send did not fully succeed. Linux returns `-EAGAIN` from
/// `__send_signal_locked` only for a real-time signal whose record could not be
/// queued; a bitmap-only loss is silent.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SendErr {
    /// `RLIMIT_SIGPENDING` / queue-depth overflow on a user-queued RT signal.
    Again,
}

/// Linux `send_signal_locked(sig, info, t, type)` — THE signal enqueue.
///
/// Runs `prepare_signal` (the SIGCONT/stop flush plus the `sig_ignored` drop),
/// picks the private or shared pending set from `target`, queues the synthesised
/// `siginfo_t`, publishes the pending bit, and wakes a thread that can take it.
///
/// `Ok(())` covers Linux's "delivered", "already pending" and "silently ignored"
/// results — none of them is an error to the caller. `Err(Again)` is the one
/// real failure: a `sigqueue(3)`-class real-time send that overflowed.
/// # C: O(N_threads) for a process-directed send; O(1) for a thread-directed one
pub fn send_signal(t: &Arc<Task>, sig: u32, src: SigSource, target: SigTarget)
    -> Result<(), SendErr>
{
    let Some(bit) = signum::bit_for(sig) else { return Ok(()) };
    // `prepare_signal`: a job-control stop and a SIGCONT cancel each other out
    // before either is queued, on BOTH sets — the pair is process state, and a
    // stop left pending on one set would re-stop a group SIGCONT just resumed.
    let flush = sigsend::prepare_flush(sig);
    if flush != 0 { flush_group(t, flush); }
    // SIGCONT resumes every stopped thread of the group before the signal is
    // even queued, so `complete_signal` cannot leave a stopped thread behind.
    if sig == Signum::Sigcont as u32 { resume_group(t); }
    if sig_ignored_for(t, sig, &src) { return Ok(()); }
    let info = sigsend::build_info(sig, src);
    let queued = if legacy_collapse(t, sig, target) {
        // `legacy_queue`: a standard signal already pending keeps its FIRST
        // record. Nothing else to do — the bit is already set.
        return Ok(());
    } else {
        push_record(t, info, target)
    };
    if !queued && sigsend::overflow_is_eagain(sig, &src) { return Err(SendErr::Again); }
    publish(t, sig, bit, target);
    Ok(())
}

/// `send_signal` for a producer running in HARD-IRQ context — POSIX timer
/// expiry off the timer tick and the one-shot deadline IRQ.
///
/// Same decisions, same queues, same publication order as [`send_signal`];
/// what differs is what a hard IRQ may touch (`06§3.1`):
///
/// * the record slot is NOT reserved here. Linux allocates a POSIX timer's
///   `struct sigqueue` once at `timer_create` (`sigqueue_alloc`) so expiry
///   never allocates; this kernel reserves the same bounded slot at
///   `timer_create` for exactly that reason, and `queues_push`'s debug
///   assertion is what proves the reservation is still there.
/// * the `prepare_signal` flush covers this task's private set and the
///   process' shared set, not the whole thread group — a sibling walk needs
///   the registry lock a hard IRQ may not take.
/// * no wake is issued here. `true` means the bit was published and the caller
///   owes the target a wake through the deferred wake list — never
///   `try_to_wake_up`'s runqueue lock and never `complete_signal`'s registry
///   walk. A process-directed signal is visible to every thread through the
///   shared set regardless of which one is roused.
/// # C: O(1)
/// # Ctx: IRQ
pub fn send_signal_irq(t: &Task, info: SigInfo, target: SigTarget) -> bool {
    let sig = info.signo;
    let Some(bit) = signum::bit_for(sig) else { return false };
    let src = SigSource::Info(info);
    let flush = sigsend::prepare_flush(sig);
    if flush != 0 { flush_local(t, flush); }
    if sig_ignored_for(t, sig, &src) { return false; }
    if legacy_collapse(t, sig, target) { return false; }
    // A dropped record is Linux's silent "loss of information": the bit is
    // still published, so the signal is delivered without its `siginfo_t`.
    let _queued = match target {
        SigTarget::Process => t.thread_group.push_shared_prealloc(info),
        SigTarget::Thread  => t.sigq_push(info),
    };
    match target {
        // `SignalPending::fetch_or` raises the signalfd `POLLIN` edge itself.
        SigTarget::Thread  => { t.sigpending.fetch_or(bit, Ordering::Release); }
        SigTarget::Process => {
            t.thread_group.publish_shared(sig);
            // The shared set has no subscriber list; raise the edge on this
            // task's own source. A hard IRQ may not walk the registry, so the
            // siblings' signalfds are reached by the woken task's delivery work
            // rather than by a group walk here.
            t.sigpending.notify_pollers();
        }
    }
    true
}

/// `prepare_signal`'s flush without the sibling walk — this task's private set
/// plus the process' shared one. # C: O(|mask|)
/// # Ctx: IRQ
fn flush_local(t: &Task, mask: u64) {
    t.thread_group.flush_shared_mask(mask);
    let cleared = t.sigpending.fetch_and(!mask, Ordering::AcqRel) & mask;
    let mut rest = cleared;
    while rest != 0 {
        let sig = rest.trailing_zeros() + 1;
        rest &= rest - 1;
        t.flush_pending_signal(sig as usize);
    }
}

/// Linux `force_sig_info_to_task`: deliver a signal the receiver cannot dodge.
/// A blocked signal is unblocked, a SIG_IGN (or any, under `HANDLER_EXIT`)
/// disposition is reset to SIG_DFL, and the record goes on the THREAD's private
/// set (`PIDTYPE_PID`) — a synchronous condition belongs to the thread that
/// caused it, not to whichever sibling happens to reach a delivery point first.
/// # C: O(1)
pub fn force_sig_info_to_task(t: &Arc<Task>, info: SigInfo, mode: ForceMode) {
    let sig = info.signo;
    let Some(bit) = signum::bit_for(sig) else { return };
    let handler = t.sigactions_ref().get(sig).handler;
    let blocked = t.sigmask.load(Ordering::Acquire);
    let d = sigsend::force_decision(handler, sig, blocked, mode);
    if d.reset_to_dfl { t.sigactions_ref().force_default(sig); }
    if d.unblock { t.sigmask.fetch_and(!bit, Ordering::AcqRel); }
    // The disposition is now guaranteed deliverable, so the `sig_ignored` arm
    // inside `send_signal` cannot drop it; `SigSource::Info` carries the full
    // `_sigfault`/`_sigsys` record straight through.
    let _ = send_signal(t, sig, SigSource::Info(info), SigTarget::Thread);
    // Linux `if (!task_sigpending(t)) signal_wake_up(t, 0)` — a signal that was
    // already pending AND blocked left the task asleep with no wake pending.
    super::sigpend::signal_wake_up(t);
}

/// Linux `force_sig_fault(sig, code, addr)`: the entry point EVERY architecture
/// fault classifier uses. Queues a full `_sigfault` record (si_code + si_addr)
/// against the faulting thread so a `signalfd`, a `sigwaitinfo` or an
/// `SA_SIGINFO` handler all see the same one, then leaves delivery to the
/// return-to-user work loop the fault vector already runs.
///
/// `addr_lsb` is the `si_addr_lsb` the SIGBUS machine-check codes carry; pass 0
/// for every other classification.
/// # C: O(1)
pub fn force_sig_fault(sig: Signum, code: i32, addr: u64, addr_lsb: i16) {
    let Some(cur) = current_arc() else { return };
    let info = sigsend::fault_info(sig.as_u8() as u32, code, addr, addr_lsb);
    force_sig_info_to_task(&cur, info, ForceMode::Current);
}

/// Linux `force_fatal_sig(sig)` — `HANDLER_SIG_DFL`: the default action runs
/// even if a handler is installed, but the task stays killable.
/// # C: O(1)
pub fn force_fatal_sig(sig: Signum, code: i32, addr: u64) {
    let Some(cur) = current_arc() else { return };
    let info = sigsend::fault_info(sig.as_u8() as u32, code, addr, 0);
    force_sig_info_to_task(&cur, info, ForceMode::SigDfl);
}

/// Linux `send_sig_info(sig, SEND_SIG_PRIV, t)` for a kernel-generated,
/// thread-directed signal (SIGPIPE on a broken pipe, SIGXFSZ past
/// `RLIMIT_FSIZE`). `si_code = SI_KERNEL`, and a SIG_IGN disposition does not
/// suppress it.
/// # C: O(1)
pub fn send_sig_priv_self(sig: Signum) {
    let Some(cur) = current_arc() else { return };
    let _ = send_signal(&cur, sig.as_u8() as u32, SigSource::Kernel, SigTarget::Thread);
    super::sigpend::signal_wake_up(&cur);
}

/// Linux `group_send_sig_info(sig, SEND_SIG_PRIV, p, PIDTYPE_TGID)` — a
/// kernel-generated PROCESS-directed signal (tty job control, the OOM killer,
/// cgroup kill, orphaned-pgrp SIGHUP/SIGCONT).
/// # C: O(N_threads)
pub fn send_sig_priv_group(t: &Arc<Task>, sig: u32) {
    let _ = send_signal(t, sig, SigSource::Kernel, SigTarget::Process);
}

/// The running task as an owned `Arc`, via the registry rather than a raw
/// `Arc::from_raw` on the runqueue slot — the forced-signal paths run in fault
/// context where a stale raw refcount op would be a use-after-free.
/// # C: O(log N)
fn current_arc() -> Option<Arc<Task>> {
    super::current().and_then(|c| crate::registry::lookup(c.tid))
}

/// Whether the send is dropped by `sig_ignored`. Reads the receiver's live
/// disposition, mask and trace state; the rule itself is ungated.
/// # C: O(1)
fn sig_ignored_for(t: &Task, sig: u32, src: &SigSource) -> bool {
    let handler = t.sigactions_ref().get(sig).handler;
    let blocked = t.sigmask.load(Ordering::Acquire);
    let ptraced = t.traced_by.load(Ordering::Acquire) != 0;
    sigsend::sig_ignored(handler, sig, blocked, src.force(), ptraced)
}

/// `legacy_queue(pending, sig)` against whichever set this send targets.
/// # C: O(1)
fn legacy_collapse(t: &Task, sig: u32, target: SigTarget) -> bool {
    let pending = match target {
        SigTarget::Thread  => t.sigpending.load(Ordering::Acquire),
        SigTarget::Process => t.thread_group.shared_pending(),
    };
    sigsend::legacy_queue(sig, pending)
}

/// Queue the record on the selected set. `false` = the bounded queue was full,
/// which is Linux's `sigqueue_alloc` returning NULL.
/// # C: O(1)
fn push_record(t: &Task, info: SigInfo, target: SigTarget) -> bool {
    match target {
        SigTarget::Process => t.thread_group.post_shared_record(info),
        SigTarget::Thread => { t.sigq_reserve(info.signo); t.sigq_push(info) }
    }
}

/// Publish the pending bit and wake a thread that can take the signal.
/// # C: O(N_threads) for a process-directed send
fn publish(t: &Arc<Task>, sig: u32, bit: u64, target: SigTarget) {
    match target {
        SigTarget::Thread => {
            t.sigpending.fetch_or(bit, Ordering::Release);
            super::registry::wake_if_stopped(t);
            super::sigpend::signal_wake_up(t);
        }
        SigTarget::Process => {
            t.thread_group.publish_shared(sig);
            let leader = t.tgid.load(Ordering::Acquire);
            // The shared set has no poll-subscriber list of its own; a signalfd
            // registers against each thread's `sigpending`.
            super::sigpend::notify_shared_pollers(leader);
            // `complete_signal` deliberately skips a thread that BLOCKS the
            // signal, because it cannot run a handler. A `signalfd` /
            // `sigwaitinfo` consumer is precisely such a thread, so a process
            // whose every thread blocks the signal would otherwise sleep
            // through it until some unrelated wake happened — the shape of a
            // PID 1 parked in `epoll_wait` on its SIGCHLD signalfd.
            if !super::sigpend::complete_signal(leader, sig) {
                super::sigpend::signalfd_notify(leader, sig);
            }
        }
    }
}

/// `prepare_signal`'s flush over the whole thread group — both the shared set
/// and every thread's private one, since a stop/cont pair can be pending in
/// either.
/// # C: O(N_threads)
fn flush_group(t: &Task, mask: u64) {
    t.thread_group.flush_shared_mask(mask);
    let tgid = t.tgid.load(Ordering::Acquire);
    for (_vtid, tid) in crate::registry::thread_entries(tgid) {
        if let Some(m) = crate::registry::lookup(tid) {
            let cleared = m.sigpending.fetch_and(!mask, Ordering::AcqRel) & mask;
            let mut rest = cleared;
            while rest != 0 {
                let sig = rest.trailing_zeros() + 1;
                rest &= rest - 1;
                m.flush_pending_signal(sig as usize);
            }
        }
    }
}

/// `prepare_signal`'s SIGCONT arm: resume every job-control-stopped member.
/// # C: O(N_threads)
fn resume_group(t: &Task) {
    let tgid = t.tgid.load(Ordering::Acquire);
    for (_vtid, tid) in crate::registry::thread_entries(tgid) {
        if let Some(m) = super::registry::lookup(tid) { super::registry::wake_if_stopped(&m); }
    }
}
