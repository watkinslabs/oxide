// `PERF_EVENT_IOC_SET_BPF` — the program an event runs when it overflows.
//
// `__perf_event_set_bpf_prog` splits on `perf_event_is_tracing()`: a
// tracepoint, kprobe or uprobe event takes a KPROBE/TRACEPOINT program and
// goes through the per-tracepoint program array, while every other event
// takes a `BPF_PROG_TYPE_PERF_EVENT` program stored directly on the event.
// oxide registers the software PMUs only — `PERF_TYPE_TRACEPOINT` and
// `PERF_TYPE_BREAKPOINT` never resolve to a PMU (`super`) — so every event
// reaching here is the non-tracing arm, `perf_event_set_bpf_handler`.
//
// The reference's release side is `perf_event_free_bpf_prog`, called from
// `_free_event`: it clears the field and drops the program's reference. Here
// the reference IS an `Arc` on the program's inode held in the event's state,
// so the event's own teardown performs that drop, and a program stays alive
// exactly as long as some event holds it plus its own descriptor.

use alloc::sync::Arc;

use security::bpf::{ProgFacts, BPF_PROG_TYPE_PERF_EVENT};
use syscall::errno::Errno;
use vfs::InodeRef;

use super::attr::PerfAttr;
use super::event::PerfEvent;
use super::uapi::{attr_bit, sample};

/// `attr.precise_ip` — the 2-bit skid-constraint field. # C: O(1)
pub fn precise_ip(attr: &PerfAttr) -> u8 {
    ((attr.bits >> attr_bit::PRECISE_IP) & 0b11) as u8
}

/// `perf_event_set_bpf_handler`'s admission, over the facts alone.
///
/// `kernel_counter` is `event->overflow_handler_context`: a hardware
/// breakpoint or an in-kernel counter already routes its overflows to a
/// kernel callback, and a program may not displace it. No oxide event has
/// one — the breakpoint PMU is not registered and nothing creates kernel
/// counters — so the call site passes `false`; the rule is enforced here so
/// it arrives with the first event that does.
///
/// A program cannot be replaced: a second `SET_BPF` on an event that already
/// carries one is `-EEXIST`, and the only thing that drops the reference is
/// the event's teardown.
/// # C: O(1)
pub fn set_bpf_check(attr: &PerfAttr, kernel_counter: bool, has_prog: bool, prog: ProgFacts)
    -> Result<(), Errno>
{
    if kernel_counter { return Err(Errno::Einval); }
    if has_prog { return Err(Errno::Eexist); }
    if prog.prog_type != BPF_PROG_TYPE_PERF_EVENT { return Err(Errno::Einval); }
    // A program that walks the stack needs the sample's own full callchain,
    // because an event constrained to a precise instruction pointer cannot
    // have one unwound for it at overflow time. Missing or half-excluded
    // callchains are refused with a distinct errno so the loader can tell
    // this apart from a program of the wrong type.
    if precise_ip(attr) != 0 && prog.call_get_stack
        && (attr.sample_type & sample::CALLCHAIN == 0
            || attr.bit(attr_bit::EXCL_CALLCHAIN_KERNEL)
            || attr.bit(attr_bit::EXCL_CALLCHAIN_USER)) {
        return Err(Errno::Eproto);
    }
    Ok(())
}

/// `PERF_EVENT_IOC_SET_BPF` on a live event: resolve the descriptor first
/// (`bpf_prog_get`, so a bad descriptor is reported before any event rule is
/// consulted), then admit, then take the reference. The already-attached test
/// and the store happen under one hold of the event's state, so two racing
/// ioctls cannot both believe the event was empty.
/// # C: O(insn count)
pub fn set_bpf(ev: &PerfEvent, fd: u32) -> Result<(), Errno> {
    let (prog, facts) = security::bpf::prog_get(fd)?;
    attach(ev, prog, facts)
}

/// Admit an already-resolved program and take its reference. Refusing drops
/// the caller's reference on return, which is the reference's `bpf_prog_put`
/// on every error path out of the ioctl. # C: O(1)
pub fn attach(ev: &PerfEvent, prog: InodeRef, facts: ProgFacts) -> Result<(), Errno> {
    let mut g = ev.state.lock();
    set_bpf_check(&ev.attr, false, g.prog.is_some(), facts)?;
    g.prog = Some(prog);
    Ok(())
}

/// `event->prog` — the program attached to a perf event, if any. Read by
/// `BPF_TASK_FD_QUERY`, which sits below this crate and is handed this
/// accessor by the syscall shim rather than keeping its own copy of which
/// events carry programs. # C: O(1)
pub fn attached_prog(inode: &InodeRef) -> Option<InodeRef> {
    let ev: Arc<PerfEvent> = super::file::event_of(inode)?;
    let prog = ev.state.lock().prog.clone();
    prog
}

#[cfg(test)]
#[path = "bpf/tests.rs"]
mod tests;
