// tracefs eventfs (`/sys/kernel/tracing/events/...`, Linux `fs/tracefs/
// event_inode.c`). A RUNTIME event registry drives the per-event directory
// hierarchy: every event gets the standard control-file set
// (`enable`/`id`/`format`/`filter`) and every subsystem + the events root get
// an aggregate `enable`/`filter`. `enable` is live (the per-event get/set fn
// pointers install/clear the tracepoint hook via `ring`); `id`/`format` are the
// fixed event descriptors; `filter` is a compiled predicate (see `predicate`):
// a write compiles the Linux filter expression against the event's `format`
// field table — invalid → EINVAL keeping the prior filter — and the event's
// emit site (`ring`) records only matching samples.
//
// The registry is mutable: built-in tracepoints are added at boot, and
// `register_dynamic_event` adds events after boot (module/tracepoint
// registration). The subsystem/event dirs iterate the registry live (the
// dynamic-inode pattern), so a runtime registration appears in `readdir` and
// `available_events` without any per-file boot wiring.

use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TraceClass};
use vfs::inode::{Inode, InodeBuilder};
use vfs::inode_ops::{default_inode_ops, mk_mode};
use vfs::file_ops::FileOps;
use vfs::{FileType, InodeRef, KResult, StaticFileInode, VfsError};

use crate::predicate::FilterSlot;
use crate::ring;

/// One tracepoint event (`events/<subsys>/<name>/`). `id`/`format` are the
/// fixed `&'static` descriptor bodies; `get`/`set` read/install the event's
/// tracepoint hook; `filter` is the compiled-predicate slot shared with the
/// event's emit site. All fields are `'static`/`Copy`, so a registry entry is a
/// plain value. # C: n/a
#[derive(Clone, Copy)]
pub struct EventDesc {
    pub subsys: &'static str,
    pub name:   &'static str,
    pub id:     &'static [u8],
    pub format: &'static [u8],
    pub get:    fn() -> bool,
    pub set:    fn(bool),
    pub filter: &'static FilterSlot,
}

/// Built-in tracepoint events. Each row's `filter` is the static slot the
/// matching emit site in `ring` reads on the hot path. # C: n/a
const BUILTIN: &[EventDesc] = &[
    EventDesc { subsys: "sched", name: "sched_switch", id: b"1\n",
                format: SCHED_SWITCH_FORMAT, get: ring::sched_switch_on, set: ring::set_sched_switch,
                filter: &ring::FILTER_SCHED_SWITCH },
    EventDesc { subsys: "syscalls", name: "sys_enter", id: b"2\n",
                format: SYS_ENTER_FORMAT, get: ring::sys_enter_on, set: ring::set_sys_enter,
                filter: &ring::FILTER_SYS_ENTER },
    EventDesc { subsys: "syscalls", name: "sys_exit", id: b"3\n",
                format: SYS_EXIT_FORMAT, get: ring::sys_exit_on, set: ring::set_sys_exit,
                filter: &ring::FILTER_SYS_EXIT },
];

/// The live event registry (built-ins + runtime registrations). # C: O(1)
static REGISTRY: Spinlock<Vec<EventDesc>, TraceClass> = Spinlock::new(Vec::new());

/// Snapshot the registry (entries are `Copy`) so callers iterate without
/// holding the lock across `get`/`set`/insert. # C: O(events)
fn snapshot() -> Vec<EventDesc> { REGISTRY.lock().clone() }

/// The distinct subsystems in the registry, in first-seen order. # C: O(events)
fn subsystems(snap: &[EventDesc]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for e in snap { if !out.contains(&e.subsys) { out.push(e.subsys); } }
    out
}

// ---- per-event filter file (compiled predicate) ----------------------------

/// `i_private` for an `events/.../filter` file: the event's filter slot. # C: O(1)
struct FilterData { slot: &'static FilterSlot }

/// `i_fop` for a per-event filter file — read echoes the stored expression
/// (`none` when unset), write compiles it against the event `format`: invalid →
/// EINVAL with the prior filter kept (Linux); valid → store + apply.
struct FilterFileOps;
impl FileOps for FilterFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<FilterData>().ok_or(VfsError::Einval)?;
        Ok(d.slot.read_into(off, buf))
    }
    fn write(&self, inode: &Inode, _off: u64, src: &[u8]) -> KResult<usize> {
        let d = inode.private::<FilterData>().ok_or(VfsError::Einval)?;
        match d.slot.set(src) { Ok(()) => Ok(src.len()), Err(_) => Err(VfsError::Einval) }
    }
}

fn make_filter_inode(slot: &'static FilterSlot) -> InodeRef {
    InodeBuilder::new(ring_alloc_ino(), mk_mode(FileType::Regular, 0o644),
                      default_inode_ops(), Arc::new(FilterFileOps))
        .private(Arc::new(FilterData { slot }))
        .build()
}

// ---- aggregate filter file (subsystem / root, plain stored string) ---------

/// `i_private` for an aggregate `filter` — Linux fans a single expression out to
/// every in-scope event; here it is a plain stored slot (per-event compiled
/// filtering is the enforced path). # C: O(1)
struct AggFilterData { val: Spinlock<Vec<u8>, TraceClass> }

struct AggFilterFileOps;
impl FileOps for AggFilterFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<AggFilterData>().ok_or(VfsError::Einval)?;
        let body = d.val.lock();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, inode: &Inode, off: u64, src: &[u8]) -> KResult<usize> {
        let d = inode.private::<AggFilterData>().ok_or(VfsError::Einval)?;
        if off == 0 { let mut v = d.val.lock(); v.clear(); v.extend_from_slice(src); }
        Ok(src.len())
    }
}

fn make_agg_filter_inode() -> InodeRef {
    InodeBuilder::new(ring_alloc_ino(), mk_mode(FileType::Regular, 0o644),
                      default_inode_ops(), Arc::new(AggFilterFileOps))
        .private(Arc::new(AggFilterData { val: Spinlock::new(b"none\n".to_vec()) }))
        .build()
}

// ---- aggregate enable (subsystem / root) -----------------------------------

/// `i_private` for an aggregate `enable`: `None` = the events root (all
/// events), `Some(sub)` = one subsystem. # C: O(1)
struct AggEnableData { subsys: Option<&'static str> }

/// `i_fop` for an aggregate enable — read "1"/"0" when every in-scope event
/// agrees, else "X" (Linux `system_enable_read`); write 0/1 toggles them all.
struct AggEnableFileOps;
impl FileOps for AggEnableFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<AggEnableData>().ok_or(VfsError::Einval)?;
        let snap = snapshot();
        let mut any_on = false;
        let mut any_off = false;
        for e in snap.iter().filter(|e| d.subsys.map_or(true, |s| e.subsys == s)) {
            if (e.get)() { any_on = true; } else { any_off = true; }
        }
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
        let snap = snapshot();
        for e in snap.iter().filter(|e| d.subsys.map_or(true, |s| e.subsys == s)) { (e.set)(on); }
        Ok(src.len())
    }
}

fn make_agg_enable_inode(subsys: Option<&'static str>) -> InodeRef {
    InodeBuilder::new(ring_alloc_ino(), mk_mode(FileType::Regular, 0o644),
                      default_inode_ops(), Arc::new(AggEnableFileOps))
        .private(Arc::new(AggEnableData { subsys }))
        .build()
}

// ---- available_events (dynamic) --------------------------------------------

/// `i_fop` for `available_events` — `sub:name\n` per registry entry, rendered
/// live so runtime registrations appear. # C: O(events)
struct AvailableEventsFileOps;
impl AvailableEventsFileOps {
    fn render() -> Vec<u8> {
        let mut out = Vec::new();
        for e in snapshot().iter() {
            out.extend_from_slice(e.subsys.as_bytes());
            out.push(b':');
            out.extend_from_slice(e.name.as_bytes());
            out.push(b'\n');
        }
        out
    }
}
impl FileOps for AvailableEventsFileOps {
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = Self::render();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
}

fn make_available_events_inode() -> InodeRef {
    InodeBuilder::new(ring_alloc_ino(), mk_mode(FileType::Regular, 0o444),
                      default_inode_ops(), Arc::new(AvailableEventsFileOps))
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

const EVENTS_BASE: &str = "/sys/kernel/tracing/events";

/// Publish one event's `events/<sub>/<name>/` dir (enable/id/format/filter).
/// Idempotent via `insert_path` (re-register overwrites a leaf). # C: O(1)
fn publish_event_dir(e: &EventDesc) {
    let base = alloc::format!("{EVENTS_BASE}/{}/{}", e.subsys, e.name);
    crate::register(&alloc::format!("{base}/enable"), ring::make_enable_inode(e.get, e.set));
    crate::register(&alloc::format!("{base}/id"),     StaticFileInode::new(e.id));
    crate::register(&alloc::format!("{base}/format"), StaticFileInode::new(e.format));
    crate::register(&alloc::format!("{base}/filter"), make_filter_inode(e.filter));
}

/// Publish a subsystem's aggregate `enable`/`filter`. # C: O(1)
fn publish_subsys_aggregate(sub: &'static str) {
    crate::register(&alloc::format!("{EVENTS_BASE}/{sub}/enable"), make_agg_enable_inode(Some(sub)));
    crate::register(&alloc::format!("{EVENTS_BASE}/{sub}/filter"), make_agg_filter_inode());
}

/// Register an event AFTER boot (tracepoint / module registration). Pushes it
/// into the registry and synthesises its dir + subsystem aggregate, so it
/// appears in `readdir`/`available_events` immediately. No-op if already
/// present. # SAFETY: caller holds a `&'static FilterSlot` for the event.
/// # C: O(events)
pub fn register_event(e: EventDesc) {
    {
        let mut g = REGISTRY.lock();
        if g.iter().any(|x| x.subsys == e.subsys && x.name == e.name) { return; }
        g.push(e);
    }
    publish_event_dir(&e);
    publish_subsys_aggregate(e.subsys);
}

/// Convenience runtime registration: leaks a `FilterSlot` for the event's
/// `format` (events outlive registration), then `register_event`. The intended
/// entry point for dynamic tracepoints. # C: O(events)
pub fn register_dynamic_event(subsys: &'static str, name: &'static str, id: &'static [u8],
                              format: &'static [u8], get: fn() -> bool, set: fn(bool)) {
    let slot: &'static FilterSlot = alloc::boxed::Box::leak(alloc::boxed::Box::new(FilterSlot::new(format)));
    register_event(EventDesc { subsys, name, id, format, get, set, filter: slot });
}

/// Register the eventfs tree under `/sys/kernel/tracing/events`. Seeds the
/// registry with the built-in tracepoints and publishes their dirs + the
/// subsystem/root aggregates + `available_events`.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(events)
pub fn register() {
    {
        let mut g = REGISTRY.lock();
        for e in BUILTIN {
            if !g.iter().any(|x| x.subsys == e.subsys && x.name == e.name) { g.push(*e); }
        }
    }
    let snap = snapshot();
    for e in snap.iter() { publish_event_dir(e); }
    for sub in subsystems(&snap) { publish_subsys_aggregate(sub); }
    crate::register(&alloc::format!("{EVENTS_BASE}/enable"), make_agg_enable_inode(None));
    // ftrace ring page/header descriptors (read by libtraceevent at open).
    crate::register(&alloc::format!("{EVENTS_BASE}/header_event"), StaticFileInode::new(HEADER_EVENT));
    crate::register(&alloc::format!("{EVENTS_BASE}/header_page"),  StaticFileInode::new(HEADER_PAGE));
    // available_events derived live from the registry (runtime events appear).
    crate::register("/sys/kernel/tracing/available_events", make_available_events_inode());
}

// ---- fixed descriptor bodies ----------------------------------------------

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
// print fmt, matching the Linux `events/<sub>/<ev>/format` layout. `pub(crate)`
// so `ring` can build each event's `FilterSlot` over the same body.
pub(crate) const SCHED_SWITCH_FORMAT: &[u8] = b"name: sched_switch\nID: 1\nformat:\n\
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\
\tfield:char prev_comm[16];\toffset:8;\tsize:16;\tsigned:0;\n\
\tfield:pid_t prev_pid;\toffset:24;\tsize:4;\tsigned:1;\n\
\tfield:char next_comm[16];\toffset:28;\tsize:16;\tsigned:0;\n\
\tfield:pid_t next_pid;\toffset:44;\tsize:4;\tsigned:1;\n\n\
print fmt: \"prev_comm=%s prev_pid=%d ==> next_comm=%s next_pid=%d\"\n";

pub(crate) const SYS_ENTER_FORMAT: &[u8] = b"name: sys_enter\nID: 2\nformat:\n\
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\
\tfield:long id;\toffset:8;\tsize:8;\tsigned:1;\n\
\tfield:unsigned long args[6];\toffset:16;\tsize:48;\tsigned:0;\n\n\
print fmt: \"NR %ld\"\n";

pub(crate) const SYS_EXIT_FORMAT: &[u8] = b"name: sys_exit\nID: 3\nformat:\n\
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\
\tfield:long id;\toffset:8;\tsize:8;\tsigned:1;\n\
\tfield:long ret;\toffset:16;\tsize:8;\tsigned:1;\n\n\
print fmt: \"NR %ld = %ld\"\n";

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::file_ops::{DirContext, DirEmit};

    fn t_get() -> bool { false }
    fn t_set(_: bool) {}

    // Collect a dir's child names via the real readdir path.
    struct Collect { names: Vec<alloc::string::String> }
    impl DirEmit for Collect {
        fn emit(&mut self, name: &str, _ino: u64, _ft: FileType, _next: u64) -> bool {
            self.names.push(name.into()); true
        }
    }
    fn readdir(dir: &InodeRef) -> Vec<alloc::string::String> {
        let mut c = Collect { names: Vec::new() };
        let mut ctx = DirContext::new(0, &mut c);
        dir.readdir(&mut ctx).unwrap();
        c.names
    }

    #[test]
    fn dynamic_event_appears_in_readdir_and_available_events() {
        register(); // seed built-ins (idempotent across the test binary's single run)
        static FMT: &[u8] = b"name: probe_foo\nID: 100\nformat:\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\
\tfield:char filename[32];\toffset:8;\tsize:32;\tsigned:0;\n";
        register_dynamic_event("myprobe", "probe_foo", b"100\n", FMT, t_get, t_set);

        // subsystem dir synthesised + listed under events/
        let evroot = crate::trace_root().lookup_path("events").unwrap();
        assert!(readdir(&evroot).iter().any(|n| n == "myprobe"));

        // event dir synthesised with the standard control files
        let evdir = crate::trace_root().lookup_path("events/myprobe/probe_foo").unwrap();
        let kids = readdir(&evdir);
        for f in ["enable", "id", "format", "filter"] { assert!(kids.iter().any(|n| n == f), "missing {f}"); }

        // available_events reflects the runtime registration
        let ae = crate::trace_root().lookup_path("available_events").unwrap();
        let mut buf = [0u8; 512];
        let n = ae.read(0, &mut buf).unwrap();
        assert!(core::str::from_utf8(&buf[..n]).unwrap().contains("myprobe:probe_foo"));
    }

    #[test]
    fn per_event_filter_compiles_and_rejects_invalid() {
        register();
        let fi = crate::trace_root().lookup_path("events/sched/sched_switch/filter").unwrap();
        // valid filter accepted + echoed back
        let w = b"prev_pid == 1234";
        assert_eq!(fi.write(0, w).unwrap(), w.len());
        let mut buf = [0u8; 64];
        let n = fi.read(0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"prev_pid == 1234\n");
        // invalid filter → EINVAL, prior kept
        assert_eq!(fi.write(0, b"no_such_field == 1"), Err(VfsError::Einval));
        let n = fi.read(0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"prev_pid == 1234\n");
        // clear
        fi.write(0, b"0").unwrap();
        let n = fi.read(0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"none\n");
    }
}
