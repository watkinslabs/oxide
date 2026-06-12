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
use alloc::collections::VecDeque;
use alloc::format;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as TraceClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// Max buffered records (ring — oldest dropped when full). Bounds memory
/// the way Linux's per-CPU `buffer_size_kb` does.
const MAX_ENTRIES: usize = 4096;

/// One recorded trace event (today: a `trace_marker` write).
struct TraceEntry {
    ts_ns: u64,
    pid:   u32,
    comm:  [u8; 16],
    clen:  usize,
    msg:   Vec<u8>,
}

static BUF: Spinlock<VecDeque<TraceEntry>, TraceClass> = Spinlock::new(VecDeque::new());
/// Linux default: tracing_on = 1 (recording enabled; the `nop` tracer just
/// doesn't generate function events — trace_marker still records).
static TRACING_ON: AtomicBool = AtomicBool::new(true);
static NEXT_INO: AtomicU64 = AtomicU64::new(0x3700_0000);

/// Monotonic ns since boot — the ftrace timestamp clock.
/// # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn now_ns() -> u64 { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn now_ns() -> u64 { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
#[cfg(not(target_os = "oxide-kernel"))]
fn now_ns() -> u64 { 0 }

/// Current task's (pid, comm) for the record header, or (0, "<kernel>").
/// # C: O(1)
fn cur_task() -> (u32, [u8; 16], usize) {
    let mut comm = [0u8; 16];
    #[cfg(target_os = "oxide-kernel")]
    if let Some(t) = sched::live::current() {
        let name = t.name.as_bytes();
        let n = name.len().min(16);
        comm[..n].copy_from_slice(&name[..n]);
        return (t.tgid.load(Ordering::Relaxed), comm, n);
    }
    let k = b"<kernel>";
    comm[..k.len()].copy_from_slice(k);
    (0, comm, k.len())
}

/// Record a `trace_marker` write. No-op when tracing_on=0. Trailing newline
/// is stripped (Linux records one marker per write without it).
/// # C: O(1) amortized
fn record_marker(msg: &[u8]) {
    if !TRACING_ON.load(Ordering::Acquire) { return; }
    let (pid, comm, clen) = cur_task();
    let trimmed = msg.strip_suffix(b"\n").unwrap_or(msg);
    let mut g = BUF.lock();
    while g.len() >= MAX_ENTRIES { g.pop_front(); }
    g.push_back(TraceEntry { ts_ns: now_ns(), pid, comm, clen, msg: trimmed.to_vec() });
}

/// Render the buffer in Linux ftrace text format. # C: O(N_entries · msg)
fn render() -> Vec<u8> {
    let g = BUF.lock();
    let mut out: Vec<u8> = Vec::with_capacity(256 + g.len() * 48);
    out.extend_from_slice(b"# tracer: nop\n#\n");
    out.extend_from_slice(format!("# entries-in-buffer/entries-written: {}/{}   #P:1\n#\n",
        g.len(), g.len()).as_bytes());
    out.extend_from_slice(b"#           TASK-PID     CPU#  TIMESTAMP  FUNCTION\n");
    out.extend_from_slice(b"#              | |         |       |         |\n");
    for e in g.iter() { fmt_entry(&mut out, e); }
    out
}

/// Append one record's Linux ftrace event line to `out`. # C: O(msg)
fn fmt_entry(out: &mut Vec<u8>, e: &TraceEntry) {
    let comm = core::str::from_utf8(&e.comm[..e.clen]).unwrap_or("?");
    let secs = e.ts_ns / 1_000_000_000;
    let usec = (e.ts_ns % 1_000_000_000) / 1_000;
    out.extend_from_slice(format!("{:>16}-{:<5} [000] ..... {}.{:06}: tracing_mark_write: ",
        comm, e.pid, secs, usec).as_bytes());
    out.extend_from_slice(&e.msg);
    out.push(b'\n');
}

/// Pop ALL buffered records and render their event lines (no header) —
/// the `trace_pipe` consuming-read path. # C: O(N_entries · msg)
fn drain_render() -> Vec<u8> {
    let mut g = BUF.lock();
    let mut out: Vec<u8> = Vec::with_capacity(g.len() * 48);
    while let Some(e) = g.pop_front() { fmt_entry(&mut out, &e); }
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
    fn write(&self, _o: u64, buf: &[u8]) -> KResult<usize> { BUF.lock().clear(); Ok(buf.len()) }
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
        if !self.pending.lock().is_empty() || !BUF.lock().is_empty() { mask |= vfs::POLL_IN; }
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
