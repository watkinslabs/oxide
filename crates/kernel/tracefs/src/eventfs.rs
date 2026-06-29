// tracefs eventfs (`/sys/kernel/tracing/events/...`, Linux `fs/tracefs/
// event_inode.c`). A single declarative event registry drives the per-event
// directory hierarchy: every event gets the standard control-file set
// (`enable`/`id`/`format`/`filter`) and every subsystem + the events root get
// an aggregate `enable`/`filter`, instead of the lone hand-registered
// `events/.../enable` leaves. `enable` is live (the per-event get/set fn
// pointers install/clear the tracepoint hook via `ring`); `id`/`format` are the
// fixed event descriptors; `filter` is a writable slot (Linux stores the filter
// expression — applied filtering rides the tracepoint-predicate follow-up).
//
// Population is table-driven (the eventfs model): adding an `Event` row
// publishes its whole `events/<sub>/<name>/` dir and folds it into the
// subsystem + root aggregate enables, with no per-file boot wiring.

use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TraceClass};
use vfs::inode::{Inode, InodeBuilder};
use vfs::inode_ops::{default_inode_ops, mk_mode};
use vfs::file_ops::FileOps;
use vfs::{FileType, InodeRef, KResult, StaticFileInode, VfsError};

use crate::ring;

/// One tracepoint event (`events/<subsys>/<name>/`). `id`/`format` are the
/// fixed `&'static` descriptor bodies; `get`/`set` read/install the event's
/// tracepoint hook. # C: n/a
struct Event {
    subsys: &'static str,
    name:   &'static str,
    id:     &'static [u8],
    format: &'static [u8],
    get:    fn() -> bool,
    set:    fn(bool),
}

/// The event registry. Mirrors `available_events`; every kernel tracepoint
/// anchor (`ring`) gets one row. # C: n/a
const EVENTS: &[Event] = &[
    Event { subsys: "sched", name: "sched_switch", id: b"1\n",
            format: SCHED_SWITCH_FORMAT, get: ring::sched_switch_on, set: ring::set_sched_switch },
    Event { subsys: "syscalls", name: "sys_enter", id: b"2\n",
            format: SYS_ENTER_FORMAT, get: ring::sys_enter_on, set: ring::set_sys_enter },
    Event { subsys: "syscalls", name: "sys_exit", id: b"3\n",
            format: SYS_EXIT_FORMAT, get: ring::sys_exit_on, set: ring::set_sys_exit },
];

/// The distinct subsystems in `EVENTS`, in first-seen order. # C: O(events)
fn subsystems() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for e in EVENTS { if !out.contains(&e.subsys) { out.push(e.subsys); } }
    out
}

// ---- writable filter slot --------------------------------------------------

/// `i_private` for an `events/.../filter` file: the stored filter expression
/// (Linux default "none"). # C: O(1)
struct FilterData { val: Spinlock<Vec<u8>, TraceClass> }

/// `i_fop` for a filter file — read returns the stored expression, write
/// replaces it (any expression is accepted; predicate evaluation is a
/// follow-up). # C: O(n)
struct FilterFileOps;
impl FileOps for FilterFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<FilterData>().ok_or(VfsError::Einval)?;
        let body = d.val.lock();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let avail = &body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, inode: &Inode, off: u64, src: &[u8]) -> KResult<usize> {
        let d = inode.private::<FilterData>().ok_or(VfsError::Einval)?;
        if off == 0 { let mut v = d.val.lock(); v.clear(); v.extend_from_slice(src); }
        Ok(src.len())
    }
}

fn make_filter_inode() -> InodeRef {
    InodeBuilder::new(ring_alloc_ino(), mk_mode(FileType::Regular, 0o644),
                      default_inode_ops(), Arc::new(FilterFileOps))
        .private(Arc::new(FilterData { val: Spinlock::new(b"none\n".to_vec()) }))
        .build()
}

// ---- aggregate enable (subsystem / root) -----------------------------------

/// `i_private` for an aggregate `enable`: `None` = the events root (all
/// events), `Some(sub)` = one subsystem. # C: O(1)
struct AggEnableData { subsys: Option<&'static str> }

/// `i_fop` for an aggregate enable — read "1"/"0" when every in-scope event
/// agrees, else "X" (Linux `system_enable_read`); write 0/1 toggles them all.
struct AggEnableFileOps;
impl AggEnableFileOps {
    fn in_scope(scope: Option<&'static str>) -> impl Iterator<Item = &'static Event> {
        EVENTS.iter().filter(move |e| scope.map_or(true, |s| e.subsys == s))
    }
}
impl FileOps for AggEnableFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<AggEnableData>().ok_or(VfsError::Einval)?;
        let mut any_on = false;
        let mut any_off = false;
        for e in Self::in_scope(d.subsys) { if (e.get)() { any_on = true; } else { any_off = true; } }
        // Linux: "X" when the set is mixed; else "1"/"0".
        let body: &[u8] = match (any_on, any_off) {
            (true, true)  => b"X\n",
            (true, false) => b"1\n",
            _             => b"0\n",
        };
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, inode: &Inode, _off: u64, src: &[u8]) -> KResult<usize> {
        let d = inode.private::<AggEnableData>().ok_or(VfsError::Einval)?;
        let on = !matches!(src.iter().find(|b| !b.is_ascii_whitespace()), Some(b'0'));
        for e in Self::in_scope(d.subsys) { (e.set)(on); }
        Ok(src.len())
    }
}

fn make_agg_enable_inode(subsys: Option<&'static str>) -> InodeRef {
    InodeBuilder::new(ring_alloc_ino(), mk_mode(FileType::Regular, 0o644),
                      default_inode_ops(), Arc::new(AggEnableFileOps))
        .private(Arc::new(AggEnableData { subsys }))
        .build()
}

/// Inode-number source shared with the rest of tracefs (kept distinct from the
/// kernfs synthetic-dir range). # C: O(1)
fn ring_alloc_ino() -> vfs::Ino {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0x3800_0000);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

// ---- population -------------------------------------------------------------

/// Register the eventfs tree under `/sys/kernel/tracing/events`. Table-driven:
/// each `Event` publishes its `enable`/`id`/`format`/`filter`; each subsystem
/// and the events root get an aggregate `enable`/`filter`; the ftrace ring
/// header descriptors round it out.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(events)
pub fn register() {
    for e in EVENTS {
        let base = alloc::format!("/sys/kernel/tracing/events/{}/{}", e.subsys, e.name);
        crate::register(&alloc::format!("{base}/enable"), ring::make_enable_inode(e.get, e.set));
        crate::register(&alloc::format!("{base}/id"),     StaticFileInode::new(e.id));
        crate::register(&alloc::format!("{base}/format"), StaticFileInode::new(e.format));
        crate::register(&alloc::format!("{base}/filter"), make_filter_inode());
    }
    for sub in subsystems() {
        crate::register(&alloc::format!("/sys/kernel/tracing/events/{sub}/enable"),
            make_agg_enable_inode(Some(sub)));
        crate::register(&alloc::format!("/sys/kernel/tracing/events/{sub}/filter"),
            make_filter_inode());
    }
    crate::register("/sys/kernel/tracing/events/enable", make_agg_enable_inode(None));
    // ftrace ring page/header descriptors (read by libtraceevent at open).
    crate::register("/sys/kernel/tracing/events/header_event", StaticFileInode::new(HEADER_EVENT));
    crate::register("/sys/kernel/tracing/events/header_page",  StaticFileInode::new(HEADER_PAGE));
    // available_events derived from the same table (kept in sync by construction).
    crate::register("/sys/kernel/tracing/available_events", StaticFileInode::new(AVAILABLE_EVENTS));
}

// ---- fixed descriptor bodies ----------------------------------------------

const AVAILABLE_EVENTS: &[u8] =
    b"sched:sched_switch\nsyscalls:sys_enter\nsyscalls:sys_exit\n";

const HEADER_PAGE: &[u8] = b"\tfield: u64 timestamp;\toffset:0;\tsize:8;\tsigned:0;\n\
\tfield: local_t commit;\toffset:8;\tsize:8;\tsigned:1;\n\
\tfield: int overwrite;\toffset:8;\tsize:1;\tsigned:1;\n\
\tfield: char data;\toffset:16;\tsize:4080;\tsigned:0;\n";

const HEADER_EVENT: &[u8] = b"# compressed entry header\n\
\ttype_len    :    5 bits\n\
\ttime_delta  :   27 bits\n\
\tarray       :   32 bits\n\
\n\
\tpadding     : type == 29\n\
\ttime_extend : type == 30\n\
\ttime_stamp  : type == 31\n\
\tdata max type_len  == 28\n";

// Each format = name/ID/format header + common fields + event-specific fields +
// print fmt, matching the Linux `events/<sub>/<ev>/format` layout.
const SCHED_SWITCH_FORMAT: &[u8] = b"name: sched_switch\nID: 1\nformat:\n\
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\
\tfield:char prev_comm[16];\toffset:8;\tsize:16;\tsigned:0;\n\
\tfield:pid_t prev_pid;\toffset:24;\tsize:4;\tsigned:1;\n\
\tfield:char next_comm[16];\toffset:28;\tsize:16;\tsigned:0;\n\
\tfield:pid_t next_pid;\toffset:44;\tsize:4;\tsigned:1;\n\n\
print fmt: \"prev_comm=%s prev_pid=%d ==> next_comm=%s next_pid=%d\"\n";

const SYS_ENTER_FORMAT: &[u8] = b"name: sys_enter\nID: 2\nformat:\n\
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\
\tfield:long id;\toffset:8;\tsize:8;\tsigned:1;\n\
\tfield:unsigned long args[6];\toffset:16;\tsize:48;\tsigned:0;\n\n\
print fmt: \"NR %ld\"\n";

const SYS_EXIT_FORMAT: &[u8] = b"name: sys_exit\nID: 3\nformat:\n\
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\
\tfield:long id;\toffset:8;\tsize:8;\tsigned:1;\n\
\tfield:long ret;\toffset:16;\tsize:8;\tsigned:1;\n\n\
print fmt: \"NR %ld = %ld\"\n";
