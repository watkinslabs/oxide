// Real ftrace trace buffer + the marker/control inodes behind
// /sys/kernel/tracing. `trace_marker` (write) timestamps a record into a
// global ring buffer; `trace` (read) renders it in Linux ftrace text
// format and (write) clears it; `tracing_on` (read/write) gates recording.
// Mirrors the kernel's `trace_marker`/`trace`/`tracing_on` debugfs files —
// the standard userspace event-injection + readback path (trace-cmd, manual
// `echo foo > trace_marker`). Per-CPU ring buffers + static tracepoints
// (sched_switch / sys_enter) ride a follow-up; this is the buffer they fill.

use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::format;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as TraceClass};
use vfs::inode::{Inode, InodeBuilder};
use vfs::inode_ops::{default_inode_ops, mk_mode};
use vfs::file_ops::FileOps;
use vfs::{FileType, Ino, InodeRef, KResult, VfsError};

use crate::percpu_ring::{self, Record, KIND_MARK, KIND_SCHED_SWITCH, KIND_SYS_ENTER, KIND_SYS_EXIT, PAYLOAD};
use crate::predicate::{EventRecord, FieldVal, FilterSlot};

/// Per-event compiled-filter slots, shared with the eventfs `filter` files
/// (`eventfs::BUILTIN` points each `EventDesc.filter` here). The emit site
/// reads them lockless when no filter is set; a set filter drops samples that
/// do not match (Linux per-event filtering). # C: O(1)
pub(crate) static FILTER_SCHED_SWITCH: FilterSlot = FilterSlot::new(crate::eventfs::SCHED_SWITCH_FORMAT);
pub(crate) static FILTER_SYS_ENTER:   FilterSlot = FilterSlot::new(crate::eventfs::SYS_ENTER_FORMAT);
pub(crate) static FILTER_SYS_EXIT:    FilterSlot = FilterSlot::new(crate::eventfs::SYS_EXIT_FORMAT);

/// Linux default: tracing_on = 1 (recording enabled; the `nop` tracer just
/// doesn't generate function events — trace_marker still records).
static TRACING_ON: AtomicBool = AtomicBool::new(true);
static NEXT_INO: AtomicU64 = AtomicU64::new(0x3700_0000);

/// Read-side serialization: `trace`/`trace_pipe` readers + clear take this so
/// concurrent drains don't double-consume. The PRODUCER side (record) is
/// lockless. # not held across blocking.
static READ_LOCK: Spinlock<(), TraceClass> = Spinlock::new(());

/// `tracing_on` gate (shared with the tracepoint sites). # C: O(1)
pub(crate) fn tracing_on() -> bool { TRACING_ON.load(Ordering::Acquire) }

/// Monotonic ns since boot — the ftrace timestamp clock. # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub(crate) fn now_ns() -> u64 { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
/// Monotonic ns since boot. # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub(crate) fn now_ns() -> u64 { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
/// Monotonic ns since boot (hosted stub). # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn now_ns() -> u64 { 0 }

/// Current CPU id (the per-CPU ring index). # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub(crate) fn this_cpu() -> usize { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() as usize }
/// Current CPU id. # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub(crate) fn this_cpu() -> usize { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() as usize }
/// Current CPU id (hosted stub). # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn this_cpu() -> usize { 0 }

/// Current task's (pid, comm[16] null-padded). # C: O(1)
fn cur_task() -> (u32, [u8; 16]) {
    #[cfg(target_os = "oxide-kernel")]
    if let Some(t) = sched::live::current() {
        return (t.tgid.load(Ordering::Relaxed), t.comm_bytes());
    }
    let mut comm = [0u8; 16];
    let k = b"<kernel>";
    comm[..k.len()].copy_from_slice(k);
    (0, comm)
}

/// Record a `trace_marker` write into this CPU's lockless ring. No-op when
/// tracing_on=0. Trailing newline stripped (one marker per write).
/// Payload layout: [comm: 16 bytes null-padded][msg bytes].
/// # C: O(1)
fn record_marker(msg: &[u8]) {
    if !tracing_on() { return; }
    let (pid, comm) = cur_task();
    let trimmed = msg.strip_suffix(b"\n").unwrap_or(msg);
    let mut pl = [0u8; PAYLOAD];
    pl[..16].copy_from_slice(&comm);
    let mn = trimmed.len().min(PAYLOAD - 16);
    pl[16..16 + mn].copy_from_slice(&trimmed[..mn]);
    percpu_ring::record(this_cpu(), now_ns(), pid, KIND_MARK, &pl[..16 + mn]);
}

/// sched_switch tracepoint hook (installed in the scheduler while the event
/// is enabled). Runs IN the context-switch hot path — IRQs off, rq lock held
/// — so it MUST stay wait-free + alloc-free: one tracing_on load, a stack
/// payload, the lockless ring record. Payload:
/// [prev_comm 16 null-pad][next_pid u32 LE][next_comm 16 null-pad].
/// # C: O(1)
fn record_sched_switch(prev_pid: u32, prev_comm: &str, next_pid: u32, next_comm: &str) {
    if !tracing_on() { return; }
    // Per-event filter (lockless when unset): drop non-matching samples.
    if FILTER_SCHED_SWITCH.has_filter() {
        let f = [
            ("prev_pid",   FieldVal::Int(prev_pid as i64)),
            ("prev_comm",  FieldVal::Str(prev_comm)),
            ("next_pid",   FieldVal::Int(next_pid as i64)),
            ("next_comm",  FieldVal::Str(next_comm)),
            ("common_pid", FieldVal::Int(prev_pid as i64)),
        ];
        if !FILTER_SCHED_SWITCH.passes(&EventRecord::new(&f)) { return; }
    }
    let mut pl = [0u8; PAYLOAD];
    let pc = prev_comm.as_bytes();
    pl[..pc.len().min(16)].copy_from_slice(&pc[..pc.len().min(16)]);
    pl[16..20].copy_from_slice(&next_pid.to_le_bytes());
    let nc = next_comm.as_bytes();
    let nn = nc.len().min(16);
    pl[20..20 + nn].copy_from_slice(&nc[..nn]);
    percpu_ring::record(this_cpu(), now_ns(), prev_pid, KIND_SCHED_SWITCH, &pl[..36]);
}

/// `events/sched/sched_switch/enable` state. Installing/clearing the scheduler
/// hook IS the enable — the switch hot path costs one null-check when off.
static SCHED_SWITCH_ON: AtomicBool = AtomicBool::new(false);

/// Enable (true) / disable the sched_switch tracepoint. # C: O(1)
pub(crate) fn set_sched_switch(on: bool) {
    SCHED_SWITCH_ON.store(on, Ordering::Release);
    #[cfg(target_os = "oxide-kernel")]
    sched::live::install_sched_switch_hook(if on { Some(record_sched_switch) } else { None });
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = record_sched_switch;
}

/// sys_enter tracepoint hook — fires per syscall in dispatch (syscall ctx, not
/// the deepest hot path but frequent). Wait-free record.
/// Payload: [comm 16 null-pad][nr u32 LE]. # C: O(1)
fn record_sys_enter(nr: u32) {
    if !tracing_on() { return; }
    let (pid, comm) = cur_task();
    if FILTER_SYS_ENTER.has_filter() {
        let f = [
            ("id",         FieldVal::Int(nr as i64)),
            ("common_pid", FieldVal::Int(pid as i64)),
        ];
        if !FILTER_SYS_ENTER.passes(&EventRecord::new(&f)) { return; }
    }
    let mut pl = [0u8; PAYLOAD];
    pl[..16].copy_from_slice(&comm);
    pl[16..20].copy_from_slice(&nr.to_le_bytes());
    percpu_ring::record(this_cpu(), now_ns(), pid, KIND_SYS_ENTER, &pl[..20]);
}

/// sys_exit tracepoint hook. Payload: [comm 16][nr u32 LE][ret i64 LE].
/// # C: O(1)
fn record_sys_exit(nr: u32, ret: i64) {
    if !tracing_on() { return; }
    let (pid, comm) = cur_task();
    if FILTER_SYS_EXIT.has_filter() {
        let f = [
            ("id",         FieldVal::Int(nr as i64)),
            ("ret",        FieldVal::Int(ret)),
            ("common_pid", FieldVal::Int(pid as i64)),
        ];
        if !FILTER_SYS_EXIT.passes(&EventRecord::new(&f)) { return; }
    }
    let mut pl = [0u8; PAYLOAD];
    pl[..16].copy_from_slice(&comm);
    pl[16..20].copy_from_slice(&nr.to_le_bytes());
    pl[20..28].copy_from_slice(&ret.to_le_bytes());
    percpu_ring::record(this_cpu(), now_ns(), pid, KIND_SYS_EXIT, &pl[..28]);
}

static SYS_ENTER_ON: AtomicBool = AtomicBool::new(false);
static SYS_EXIT_ON: AtomicBool = AtomicBool::new(false);

/// Enable/disable the sys_enter tracepoint. # C: O(1)
pub(crate) fn set_sys_enter(on: bool) {
    SYS_ENTER_ON.store(on, Ordering::Release);
    syscall::tracepoint::install_sys_enter_hook(if on { Some(record_sys_enter) } else { None });
}
/// Enable/disable the sys_exit tracepoint. # C: O(1)
pub(crate) fn set_sys_exit(on: bool) {
    SYS_EXIT_ON.store(on, Ordering::Release);
    syscall::tracepoint::install_sys_exit_hook(if on { Some(record_sys_exit) } else { None });
}

/// Trim a null-padded comm field to its stored bytes. # C: O(n)
fn comm_bytes(b: &[u8]) -> &[u8] {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    &b[..end]
}

/// Render one byte as a readable trace field without losing identity. # C: O(1)
fn append_trace_byte(out: &mut Vec<u8>, b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    match b {
        b' '..=b'~' if b != b'\\' => out.push(b),
        _ => {
            out.extend_from_slice(b"\\x");
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0f) as usize]);
        }
    }
}

/// Escaped byte length for a trace comm field. # C: O(n)
fn trace_bytes_len(b: &[u8]) -> usize {
    b.iter().map(|c| if matches!(*c, b' '..=b'~') && *c != b'\\' { 1 } else { 4 }).sum()
}

/// Append a byte-preserving trace comm field. # C: O(n)
fn append_comm(out: &mut Vec<u8>, b: &[u8]) {
    for c in comm_bytes(b).iter().copied() { append_trace_byte(out, c); }
}

/// Append the fixed-width ftrace task column. # C: O(n)
fn append_comm_col(out: &mut Vec<u8>, b: &[u8]) {
    let comm = comm_bytes(b);
    let len = trace_bytes_len(comm);
    for _ in len..16 { out.push(b' '); }
    for c in comm.iter().copied() { append_trace_byte(out, c); }
}

/// Append one record's Linux ftrace event line to `out`. # C: O(payload)
fn fmt_record(out: &mut Vec<u8>, e: &Record) {
    let secs = e.ts_ns / 1_000_000_000;
    let usec = (e.ts_ns % 1_000_000_000) / 1_000;
    let p = e.data();
    match e.kind {
        KIND_MARK if p.len() >= 16 => {
            append_comm_col(out, &p[..16]);
            out.extend_from_slice(format!("-{:<5} [{:03}] ..... {}.{:06}: tracing_mark_write: ",
                e.pid, e.cpu, secs, usec).as_bytes());
            out.extend_from_slice(&p[16..]);
            out.push(b'\n');
        }
        KIND_SCHED_SWITCH if p.len() >= 16 + 4 + 16 => {
            // [prev_comm 16][next_pid u32 LE][next_comm 16]
            let next_pid = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
            append_comm_col(out, &p[..16]);
            out.extend_from_slice(format!("-{:<5} [{:03}] ..... {}.{:06}: sched_switch: prev_comm=",
                e.pid, e.cpu, secs, usec).as_bytes());
            append_comm(out, &p[..16]);
            out.extend_from_slice(format!(" prev_pid={} ==> next_comm=", e.pid).as_bytes());
            append_comm(out, &p[20..36]);
            out.extend_from_slice(format!(" next_pid={}\n", next_pid).as_bytes());
        }
        KIND_SYS_ENTER if p.len() >= 16 + 4 => {
            let nr = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
            append_comm_col(out, &p[..16]);
            out.extend_from_slice(format!("-{:<5} [{:03}] ..... {}.{:06}: sys_enter: NR {}\n",
                e.pid, e.cpu, secs, usec, nr).as_bytes());
        }
        KIND_SYS_EXIT if p.len() >= 16 + 4 + 8 => {
            let nr = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
            let ret = i64::from_le_bytes([p[20], p[21], p[22], p[23], p[24], p[25], p[26], p[27]]);
            append_comm_col(out, &p[..16]);
            out.extend_from_slice(format!("-{:<5} [{:03}] ..... {}.{:06}: sys_exit: NR {} = {}\n",
                e.pid, e.cpu, secs, usec, nr, ret).as_bytes());
        }
        _ => {}
    }
}

/// Render an ftrace `trace` snapshot (header + all unconsumed records,
/// timestamp-ordered; non-destructive). # C: O(N · payload)
fn render() -> Vec<u8> {
    let _g = READ_LOCK.lock();
    let recs = percpu_ring::collect(false);
    let mut out: Vec<u8> = Vec::with_capacity(256 + recs.len() * 64);
    out.extend_from_slice(b"# tracer: nop\n#\n");
    out.extend_from_slice(format!("# entries-in-buffer/entries-written: {}/{}   #P:1\n#\n",
        recs.len(), recs.len()).as_bytes());
    out.extend_from_slice(b"#           TASK-PID     CPU#  TIMESTAMP  FUNCTION\n");
    out.extend_from_slice(b"#              | |         |       |         |\n");
    for e in recs.iter() { fmt_record(&mut out, e); }
    out
}

/// Drain ALL records, render their event lines (no header) — `trace_pipe`'s
/// consuming read. # C: O(N · payload)
fn drain_render() -> Vec<u8> {
    let _g = READ_LOCK.lock();
    let recs = percpu_ring::collect(true);
    let mut out: Vec<u8> = Vec::with_capacity(recs.len() * 64);
    for e in recs.iter() { fmt_record(&mut out, e); }
    out
}

/// Serve `body[off..]` into `buf` (the dynamic-read pattern). # C: O(n)
fn read_at(body: &[u8], off: u64, buf: &mut [u8]) -> usize {
    let off = off as usize;
    if off >= body.len() { return 0; }
    let avail = &body[off..];
    let n = avail.len().min(buf.len());
    buf[..n].copy_from_slice(&avail[..n]);
    n
}

fn alloc_ino() -> Ino { NEXT_INO.fetch_add(1, Ordering::Relaxed) }

pub(crate) fn sched_switch_on() -> bool { SCHED_SWITCH_ON.load(Ordering::Acquire) }
pub(crate) fn sys_enter_on() -> bool { SYS_ENTER_ON.load(Ordering::Acquire) }
pub(crate) fn sys_exit_on() -> bool { SYS_EXIT_ON.load(Ordering::Acquire) }

/// Build an `events/.../enable` inode for the eventfs model (per-event
/// tracepoint get/set fn pointers). # C: O(1)
pub(crate) fn make_enable_inode(get: fn() -> bool, set: fn(bool)) -> InodeRef {
    make_trace_inode(TraceFile::Enable { get, set }, 2)
}

/// Which `/sys/kernel/tracing` control file an inode backs — the `i_private`
/// payload (`TraceData`). One shared `i_fop` (`TraceFileOps`) dispatches on it,
/// so every trace file shares one vtable. Each variant carries only its
/// per-file state (the per-event get/set fn pointers for `Enable`, the
/// consume-buffer for `Pipe`).
enum TraceFile {
    /// `trace_marker` — write records a marker; read is empty.
    Marker,
    /// `trace` — read renders the buffer; write clears it.
    Trace,
    /// `tracing_on` — read "1\n"/"0\n"; write toggles.
    TracingOn,
    /// `events/<sub>/<event>/enable` — read "1\n"/"0\n"; write 1/0 installs or
    /// clears the event's tracepoint hook (per-event get/set fn pointers).
    Enable { get: fn() -> bool, set: fn(bool) },
    /// `trace_pipe` — the CONSUMING ftrace reader. Unlike `trace`
    /// (non-destructive snapshot), each read drains records out of the buffer
    /// and renders their event lines (no header). A blocking read parks until a
    /// record is available (Linux trace_pipe blocks by default); O_NONBLOCK
    /// reads return EAGAIN on an empty buffer. `pending` holds bytes already
    /// rendered but not yet copied to the reader (so a short read never drops a
    /// record).
    Pipe { pending: Spinlock<Vec<u8>, TraceClass> },
}

/// Backend-private state (`i_private`) for a trace control-file inode. # C: O(1)
struct TraceData { file: TraceFile }

/// Recover the per-file state from a trace inode's `i_private`. # C: O(1)
fn trace_data(inode: &Inode) -> KResult<&TraceData> {
    inode.private::<TraceData>().ok_or(VfsError::Einval)
}

/// Copy from `pending` front into `buf`; drop the served bytes. Refills
/// `pending` from a buffer drain first if it is empty. Returns bytes served
/// (0 only when both `pending` and the buffer are empty). # C: O(n)
fn pipe_serve(pending: &Spinlock<Vec<u8>, TraceClass>, buf: &mut [u8]) -> usize {
    let mut p = pending.lock();
    if p.is_empty() {
        let drained = drain_render();
        if drained.is_empty() { return 0; }
        *p = drained;
    }
    let n = p.len().min(buf.len());
    buf[..n].copy_from_slice(&p[..n]);
    p.drain(..n);
    n
}

/// '0' (first non-space byte) disables, anything else (incl. '1') enables —
/// the shared `tracing_on`/`enable` write parse (Linux `echo 0|1 > file`).
/// # C: O(buf)
fn parse_on(buf: &[u8]) -> bool {
    !matches!(buf.iter().find(|b| !b.is_ascii_whitespace()), Some(b'0'))
}

/// Shared `file_operations` for every `/sys/kernel/tracing` control file;
/// dispatches on the `TraceFile` variant in `i_private`.
struct TraceFileOps;
impl FileOps for TraceFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        match &trace_data(inode)?.file {
            TraceFile::Marker => Ok(0),
            TraceFile::Trace => Ok(read_at(&render(), off, buf)),
            TraceFile::TracingOn => {
                let body: &[u8] = if TRACING_ON.load(Ordering::Acquire) { b"1\n" } else { b"0\n" };
                Ok(read_at(body, off, buf))
            }
            TraceFile::Enable { get, .. } => {
                let body: &[u8] = if get() { b"1\n" } else { b"0\n" };
                Ok(read_at(body, off, buf))
            }
            // Blocking read: park (tick-yield) until a record is available, then
            // drain. Mirrors the console/pty yield-loop; no busy spin on the lock.
            TraceFile::Pipe { pending } => loop {
                let n = pipe_serve(pending, buf);
                if n > 0 { return Ok(n); }
                #[cfg(target_os = "oxide-kernel")]
                // SAFETY: tracefs read runs in process syscall context with the
                // runqueue installed; tick_yield reschedules until data arrives.
                unsafe { sched::live::tick_yield(); }
                #[cfg(not(target_os = "oxide-kernel"))]
                return Ok(0);
            },
        }
    }

    /// O_NONBLOCK read: only `trace_pipe` differs (EAGAIN on empty); every other
    /// trace file never blocks, so the default forward-to-`read` is correct.
    fn read_nonblock(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        match &trace_data(inode)?.file {
            TraceFile::Pipe { pending } => {
                let n = pipe_serve(pending, buf);
                if n == 0 { Err(VfsError::Eagain) } else { Ok(n) }
            }
            _ => self.read(inode, off, buf),
        }
    }

    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        match &trace_data(inode)?.file {
            TraceFile::Marker => { record_marker(buf); Ok(buf.len()) }
            // Any write clears the buffer (Linux `echo > trace`).
            TraceFile::Trace => { percpu_ring::clear(); Ok(buf.len()) }
            TraceFile::TracingOn => { TRACING_ON.store(parse_on(buf), Ordering::Release); Ok(buf.len()) }
            TraceFile::Enable { set, .. } => { set(parse_on(buf)); Ok(buf.len()) }
            // trace_pipe is read-only (Linux: no write op) → EINVAL.
            TraceFile::Pipe { .. } => Err(VfsError::Einval),
        }
    }

    fn poll(&self, inode: &Inode) -> u32 {
        match trace_data(inode) {
            Ok(d) => match &d.file {
                TraceFile::Pipe { pending } => {
                    let mut mask = 0;
                    if !pending.lock().is_empty() || percpu_ring::any_pending() { mask |= vfs::POLL_IN; }
                    mask
                }
                // Synthetic files never block → always ready (the generic default).
                _ => vfs::POLL_IN | vfs::POLL_OUT,
            },
            Err(_) => vfs::POLL_IN | vfs::POLL_OUT,
        }
    }
}

/// Build a `/sys/kernel/tracing` control-file inode (`S_IFREG|0o644`) backed by
/// `file`, with `i_size` snapshot `size`. The read path bounds on EOF, not
/// `i_size`. # C: O(1)
fn make_trace_inode(file: TraceFile, size: u64) -> InodeRef {
    InodeBuilder::new(alloc_ino(), mk_mode(FileType::Regular, 0o644),
                      default_inode_ops(), Arc::new(TraceFileOps))
        .size(size)
        .private(Arc::new(TraceData { file }))
        .build()
}

/// Register the dynamic trace inodes. Replaces the static placeholders for
/// `trace` / `trace_marker` / `trace_pipe` / `tracing_on`. # C: O(1)
pub fn register() {
    crate::register("/sys/kernel/tracing/trace_marker",
        make_trace_inode(TraceFile::Marker, 0));
    crate::register("/sys/kernel/tracing/trace",
        make_trace_inode(TraceFile::Trace, render().len() as u64));
    crate::register("/sys/kernel/tracing/trace_pipe",
        make_trace_inode(TraceFile::Pipe { pending: Spinlock::new(Vec::new()) }, 0));
    crate::register("/sys/kernel/tracing/tracing_on",
        make_trace_inode(TraceFile::TracingOn, 2));
    // The per-event `events/.../enable` leaves are registered by the eventfs
    // model (`eventfs::register`), which also adds id/format/filter + the
    // subsystem/root aggregate enables.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comm_renderer_preserves_non_utf8_bytes() {
        let mut out = Vec::new();
        append_comm(&mut out, b"raw\xff\\x\0ignored");
        assert_eq!(&out, b"raw\\xff\\x5cx");
    }

    #[test]
    fn comm_column_pads_by_rendered_width() {
        let mut out = Vec::new();
        append_comm_col(&mut out, b"a\xff\0");
        assert_eq!(&out, b"           a\\xff");
    }
}
