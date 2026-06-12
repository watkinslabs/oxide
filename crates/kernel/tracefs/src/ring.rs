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
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

use crate::percpu_ring::{self, Record, KIND_MARK, KIND_SCHED_SWITCH, PAYLOAD};

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
    let mut comm = [0u8; 16];
    #[cfg(target_os = "oxide-kernel")]
    if let Some(t) = sched::live::current() {
        let name = t.name.as_bytes();
        let n = name.len().min(16);
        comm[..n].copy_from_slice(&name[..n]);
        return (t.tgid.load(Ordering::Relaxed), comm);
    }
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

/// trim a null-padded comm field to its &str.
fn comm_str(b: &[u8]) -> &str {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    core::str::from_utf8(&b[..end]).unwrap_or("?")
}

/// Append one record's Linux ftrace event line to `out`. # C: O(payload)
fn fmt_record(out: &mut Vec<u8>, e: &Record) {
    let secs = e.ts_ns / 1_000_000_000;
    let usec = (e.ts_ns % 1_000_000_000) / 1_000;
    let p = e.data();
    match e.kind {
        KIND_MARK if p.len() >= 16 => {
            let comm = comm_str(&p[..16]);
            out.extend_from_slice(format!("{:>16}-{:<5} [{:03}] ..... {}.{:06}: tracing_mark_write: ",
                comm, e.pid, e.cpu, secs, usec).as_bytes());
            out.extend_from_slice(&p[16..]);
            out.push(b'\n');
        }
        KIND_SCHED_SWITCH if p.len() >= 16 + 4 + 16 + 4 => {
            // [prev_comm 16][next_pid u32 LE][next_comm 16][next state u8...]
            let prev_comm = comm_str(&p[..16]);
            let next_pid = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
            let next_comm = comm_str(&p[20..36]);
            out.extend_from_slice(format!(
                "{:>16}-{:<5} [{:03}] ..... {}.{:06}: sched_switch: prev_comm={} prev_pid={} ==> next_comm={} next_pid={}\n",
                prev_comm, e.pid, e.cpu, secs, usec, prev_comm, e.pid, next_comm, next_pid).as_bytes());
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

/// `/sys/kernel/tracing/trace_marker` — write records a marker; read is empty.
struct TraceMarkerInode { ino: Ino }
impl Inode for TraceMarkerInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, buf: &[u8]) -> KResult<usize> { record_marker(buf); Ok(buf.len()) }
}

/// `/sys/kernel/tracing/trace` — read renders the buffer; write clears it.
struct TraceInode { ino: Ino }
impl Inode for TraceInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { render().len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(read_at(&render(), off, buf)) }
    /// Any write clears the buffer (Linux `echo > trace`). # C: O(1)
    fn write(&self, _o: u64, buf: &[u8]) -> KResult<usize> { percpu_ring::clear(); Ok(buf.len()) }
}

/// `/sys/kernel/tracing/tracing_on` — read "1\n"/"0\n"; write toggles.
struct TracingOnInode { ino: Ino }
impl Inode for TracingOnInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 2 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body: &[u8] = if TRACING_ON.load(Ordering::Acquire) { b"1\n" } else { b"0\n" };
        Ok(read_at(body, off, buf))
    }
    fn write(&self, _o: u64, buf: &[u8]) -> KResult<usize> {
        // First non-space byte '0' disables, anything else (incl. '1') enables.
        let on = !matches!(buf.iter().find(|b| !b.is_ascii_whitespace()), Some(b'0'));
        TRACING_ON.store(on, Ordering::Release);
        Ok(buf.len())
    }
}

/// `/sys/kernel/tracing/trace_pipe` — the CONSUMING ftrace reader. Unlike
/// `trace` (non-destructive snapshot), each read drains records out of the
/// buffer and renders their event lines (no header). A blocking read parks
/// until a record is available (Linux trace_pipe blocks by default);
/// O_NONBLOCK reads return EAGAIN on an empty buffer. `pending` holds bytes
/// already rendered but not yet copied to the reader (so a short read never
/// drops a record).
struct TracePipeInode { ino: Ino, pending: Spinlock<Vec<u8>, TraceClass> }

impl TracePipeInode {
    /// Copy from `pending` front into `buf`; drop the served bytes. Refills
    /// `pending` from a buffer drain first if it is empty. Returns bytes
    /// served (0 only when both `pending` and the buffer are empty).
    fn serve(&self, buf: &mut [u8]) -> usize {
        let mut p = self.pending.lock();
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
}

impl Inode for TracePipeInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    /// Blocking read: park (tick-yield) until a record is available, then
    /// drain. Mirrors the console/pty yield-loop; no busy spin on the lock.
    fn read(&self, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        loop {
            let n = self.serve(buf);
            if n > 0 { return Ok(n); }
            #[cfg(target_os = "oxide-kernel")]
            // SAFETY: tracefs read runs in process syscall context with the
            // runqueue installed; tick_yield reschedules until data arrives.
            unsafe { sched::live::tick_yield(); }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Ok(0);
        }
    }
    /// O_NONBLOCK read: EAGAIN when the buffer is empty.
    fn read_nonblock(&self, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        let n = self.serve(buf);
        if n == 0 { Err(VfsError::Eagain) } else { Ok(n) }
    }
    fn poll(&self) -> u32 {
        let mut mask = 0;
        if !self.pending.lock().is_empty() || percpu_ring::any_pending() { mask |= vfs::POLL_IN; }
        mask
    }
}

/// Register the dynamic trace inodes. Replaces the static placeholders for
/// `trace` / `trace_marker` / `trace_pipe` / `tracing_on`. # C: O(1)
pub fn register() {
    devfs::register("/sys/kernel/tracing/trace_marker",
        Arc::new(TraceMarkerInode { ino: alloc_ino() }) as InodeRef);
    devfs::register("/sys/kernel/tracing/trace",
        Arc::new(TraceInode { ino: alloc_ino() }) as InodeRef);
    devfs::register("/sys/kernel/tracing/trace_pipe",
        Arc::new(TracePipeInode { ino: alloc_ino(), pending: Spinlock::new(Vec::new()) }) as InodeRef);
    devfs::register("/sys/kernel/tracing/tracing_on",
        Arc::new(TracingOnInode { ino: alloc_ino() }) as InodeRef);
}
