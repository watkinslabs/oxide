use alloc::vec::Vec;

use super::io_files::io_body_for_task;
use super::pid_ino;
use super::self_files::{push, push_hex, push_u64};
use vfs::InodeRef;

fn pid_status_body(tid: u32) -> Vec<u8> {
    crate::pid_status::body(tid)
}

fn pid_cmdline_body(tid: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    let task = match sched::live::registry::lookup(tid) {
        Some(t) => t,
        None => return out,
    };
    // If PR_SET_MM rewrote the argv region (systemd relabels its cmdline
    // this way), emit the raw [arg_start, arg_end) bytes read from the
    // task's own address space — that is what `/proc/pid/cmdline` sources
    // in Linux (`get_mm_cmdline`). Gated on the user-set flag: at exec
    // baseline the correct-order `task.cmdline` snapshot is used instead.
    if let Some(bytes) = foreign_region_bytes(tid, true) { return bytes; }
    let snap = task.cmdline();
    if let Some(s) = snap {
        push(&mut out, s.as_bytes());
    } else {
        push(&mut out, task.comm().as_bytes());
        out.push(0);
    }
    out
}

/// Read a task's argv (`arg`=true) or env region from its own address
/// space, exactly like Linux `get_mm_cmdline`/`environ_read` source the
/// raw `[arg_start,arg_end)`/`[env_start,env_end)` bytes. The exec stack
/// builder lays argv/env FORWARD (argv[0] lowest), so the baseline region
/// is already correct-order and needs no gate. `None` (→ caller falls back
/// to the snapshot) when the bounds are unset (arg_start==0: kernel thread /
/// no argv) or the AS has no real PT root. Bounded to ARG_MAX (128 KiB).
fn foreign_region_bytes(tid: u32, arg: bool) -> Option<Vec<u8>> {
    let task = sched::live::registry::lookup(tid)?;
    // task is a foreign task (arbitrary tid): clone_mm pins against a
    // concurrent exit/execve mm replacement on another CPU.
    let mm = task.clone_mm()?;
    let (start, end) = if arg { (mm.arg_start(), mm.arg_end()) } else { (mm.env_start(), mm.env_end()) };
    if start == 0 || end <= start { return None; }
    let root = mm.root_pa();
    if root == 0 { return None; }
    let len = ((end - start) as usize).min(128 * 1024);
    let mut buf = alloc::vec![0u8; len];
    // SAFETY: root is this live mm's PT root (Arc held); read-only foreign walk over the [start,end) user region.
    let n = unsafe { pmm::user_as::read_foreign_user(root, start, &mut buf) };
    buf.truncate(n);
    Some(buf)
}

fn pid_stat_body(tid: u32) -> Vec<u8> {
    crate::pid_stat::body(tid)
}

fn pid_maps_body(tid: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);
    let task = match sched::live::registry::lookup(tid) {
        Some(t) => t,
        None => return out,
    };
    // task is a foreign task (arbitrary tid): clone_mm pins against a
    // concurrent exit/execve mm replacement on another CPU.
    let mm = match task.clone_mm() {
        Some(m) => m,
        None => return out,
    };
    for vma in mm.snapshot_vmas() {
        push_hex(&mut out, vma.start.as_u64());
        out.push(b'-');
        push_hex(&mut out, vma.end.as_u64());
        out.push(b' ');
        let p = vma.prot;
        out.push(if p.contains(vmm::VmaProt::READ) { b'r' } else { b'-' });
        out.push(if p.contains(vmm::VmaProt::WRITE) { b'w' } else { b'-' });
        out.push(if p.contains(vmm::VmaProt::EXEC) { b'x' } else { b'-' });
        out.push(if vma.flags.contains(vmm::VmaFlags::SHARED) { b's' } else { b'p' });
        push(&mut out, b" 00000000 00:00 0 ");
        if let Some(name) = vma.anon_name.as_ref() {
            push(&mut out, b"[anon:"); push(&mut out, name.as_bytes()); push(&mut out, b"]");
        }
        out.push(b'\n');
    }
    out
}

macro_rules! pid_inode_ctor {
    ($ctor:ident, $body:ident, $tag:expr) => {
        pub fn $ctor(tid: u32) -> InodeRef {
            crate::dyn_file::make_pid_gen_file(pid_ino($tag, tid), tid, $body)
        }
    };
}

pid_inode_ctor!(make_pid_status, pid_status_body, 0x20);
pid_inode_ctor!(make_pid_cmdline, pid_cmdline_body, 0x21);
pid_inode_ctor!(make_pid_stat, pid_stat_body, 0x22);
pid_inode_ctor!(make_pid_maps, pid_maps_body, 0x23);
pid_inode_ctor!(make_pid_comm, pid_comm_body, 0x24);
pid_inode_ctor!(make_pid_environ, pid_environ_body, 0x25);
pid_inode_ctor!(make_pid_statm, pid_statm_body, 0x26);
pid_inode_ctor!(make_pid_io, pid_io_body, 0x29);
pid_inode_ctor!(make_pid_limits, pid_limits_body, 0x28);
use crate::pid_sched::pid_sched_body;
pid_inode_ctor!(make_pid_sched, pid_sched_body, 0x27);
pid_inode_ctor!(make_pid_personality, pid_personality_body, 0x2e);

/// Linux `proc_pid_personality`: `seq_printf(m, "%08x\n", task->personality)`.
/// It was a hardcoded `00000000`, so `setarch`/`personality(2)` state was
/// invisible in `/proc` and disagreed with what the syscall reported — a split
/// source of truth for the same per-task field.
/// # C: O(1)
fn pid_personality_body(tid: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    let Some(task) = sched::live::registry::lookup(tid) else { return out };
    let persona = sched::personality::get(&task);
    for shift in (0..8).rev() {
        let nib = ((persona >> (shift * 4)) & 0xf) as u8;
        out.push(if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) });
    }
    out.push(b'\n');
    out
}

fn pid_io_body(tid: u32) -> Vec<u8> {
    match sched::live::registry::lookup(tid) {
        Some(t) => io_body_for_task(&t),
        None    => Vec::new(),
    }
}

fn pid_limits_body(tid: u32) -> Vec<u8> {
    match sched::live::registry::lookup(tid) {
        Some(t) => limits_body_for_task(&t),
        None    => Vec::new(),
    }
}

/// `/proc/self/limits` — the SAME renderer `/proc/<pid>/limits` uses, run
/// against the running task. `/proc/self/limits` previously served a hardcoded
/// static blob whose contents contradicted both the real defaults and the
/// per-pid file, so `setrlimit(2)` changes were invisible through it and the
/// two paths disagreed. # C: O(1)
pub fn self_limits_body() -> Vec<u8> {
    // No current task (early boot, a kthread) does not mean "no limits": it
    // means the init table, which is what a task would inherit. Returning an
    // EMPTY body here would be a different answer, not a missing one — the
    // same shape as the UTS reader that returned "" instead of the init
    // namespace's name and panicked the boot self-check (B1442). Rendering
    // `DEFAULT_RLIMITS` through the one renderer keeps a single source of
    // truth and never hands userspace a truncated file.
    match sched::live::current() {
        Some(t) => limits_body_for_task(t),
        None    => crate::limits_render::limits_body_for_table(&sched::rlimit::DEFAULT_RLIMITS),
    }
}

/// Linux `proc_pid_limits` — one row per `RLIMIT_*` from the task's live
/// process-wide table. The rendering itself lives in `crate::limits_render`,
/// outside this target-gated module, so it is hosted-testable. # C: O(1)
pub fn limits_body_for_task(task: &sched::Task) -> Vec<u8> {
    crate::limits_render::limits_body_for_table(&task.all_rlimits())
}

fn pid_statm_body(tid: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    let task = match sched::live::registry::lookup(tid) {
        Some(t) => t,
        None => return out,
    };
    // task is a foreign task (arbitrary tid): clone_mm pins against a
    // concurrent exit/execve mm replacement on another CPU.
    let pages = match task.clone_mm() {
        Some(mm) => mm.snapshot_vmas().iter().map(|v| (v.end.as_u64() - v.start.as_u64()) / 4096).sum::<u64>(),
        None => 0,
    };
    push_u64(&mut out, pages);
    out.push(b' ');
    push_u64(&mut out, pages);
    out.push(b' ');
    push(&mut out, b"0 0 0 0 0\n");
    out
}

fn pid_comm_body(tid: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    let task = match sched::live::registry::lookup(tid) {
        Some(t) => t,
        None => return out,
    };
    // `comm()`: the single canonical per-thread name (spawn/exec/prctl
    // PR_SET_NAME), same accessor `/proc/<pid>/stat` field 2 reads —
    // one source of truth for both files.
    push(&mut out, task.comm().as_bytes());
    out.push(b'\n');
    out
}

fn pid_environ_body(tid: u32) -> Vec<u8> {
    let task = match sched::live::registry::lookup(tid) {
        Some(t) => t,
        None => return Vec::new(),
    };
    // PR_SET_MM_ENV_START/END rewrite: read the raw [env_start, env_end)
    // region from the task's AS (Linux `environ_read`). Gated on the
    // user-set flag; else the exec-time snapshot. (Owner/ptrace access
    // control is enforced at the /proc file open, unchanged here.)
    if let Some(bytes) = foreign_region_bytes(tid, false) { return bytes; }
    match task.environ() {
        Some(s) => s.into_bytes(),
        None => Vec::new(),
    }
}
