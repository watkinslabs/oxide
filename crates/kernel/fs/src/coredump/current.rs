// Snapshot the dying process and send its dump wherever the pattern says.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::pattern::{self, CoreContext, CoreKind};

/// Nanoseconds per second, for the wall-clock stamp a pattern can interpolate.
const NS_PER_SEC: u64 = 1_000_000_000;

/// Granularity `RLIMIT_CORE` truncates on. Linux emits the memory half of a
/// dump one page at a time (`dump_user_range`), so the limit binds at a page
/// boundary rather than mid-page.
const DUMP_CHUNK: usize = hal::PAGE_SIZE_BYTES as usize;

/// Dump the running process, killed by `signo`.
///
/// Best-effort: the process is already terminating, so a failure to deliver the
/// dump cannot be reported to anyone. It is never papered over as success —
/// a pattern naming a program that does not exist produces no dump and no file.
/// # C: O(dump size)
pub fn write_for_current(signo: i32) {
    let Some(cur) = sched::live::current() else { return };
    let cx = snapshot(&cur, signo);
    let raw = pattern::core_pattern();
    let kind = pattern::kind_of(trim(&raw));

    // A program collects the dump itself and is not subject to the size limit —
    // nothing is written to a filesystem, and Linux overwrites `cprm->limit`
    // with RLIM_INFINITY once the helper is chosen. A file destination is
    // bounded: a zero limit is how a system says it does not want core files.
    if kind == CoreKind::File && !sched::rlimit::dump::file_dump_enabled(cx.rlimit_core) { return; }

    let body = super::elf::build_coredump(signo, &cur.comm(), cx.vpid);
    match kind {
        CoreKind::Pipe => { super::pipe::dump_to_program(trim(&raw), &cx, &body); }
        // Linux `dump_emit` refuses the first chunk that would cross the limit,
        // so an over-limit dump is TRUNCATED rather than dropped — a partial
        // core is still worth having, and gdb reads it.
        CoreKind::File => {
            let n = sched::rlimit::dump::prefix_len(body.len(), cx.rlimit_core, DUMP_CHUNK);
            write_to_file(&pattern::file_path(&raw, &cx), &body[..n]);
        }
        // A socket destination needs a connection to a listener that this
        // kernel has no path to yet, so nothing is delivered. Writing a file
        // instead would put the dump somewhere the operator did not ask for.
        CoreKind::Socket => {}
    }
}

fn trim(p: &[u8]) -> &[u8] {
    let mut end = p.len();
    while end > 0 && (p[end - 1] == b'\n' || p[end - 1] == b'\r') { end -= 1; }
    &p[..end]
}

fn write_to_file(path: &str, body: &[u8]) {
    let inode = crate::tmpfs::tmpfs_anon_file();
    let _ = inode.write(0, body);
    devfs::register(alloc::boxed::Box::leak(alloc::string::String::from(path).into_boxed_str()), inode);
}

fn snapshot(cur: &sched::Task, signo: i32) -> CoreContext {
    let (core_soft, _) = cur.rlimit(sched::rlimit::rlim::CORE);
    let vtgid = cur.vtgid.load(Ordering::Acquire);
    let vtid = cur.vtid.load(Ordering::Acquire);
    let mut exe: Vec<u8> = Vec::new();
    cur.with_exe_path(|p| if let Some(p) = p { exe.extend_from_slice(p.as_bytes()); });
    CoreContext {
        signo,
        vpid: if vtgid != 0 { vtgid } else { cur.tgid.load(Ordering::Acquire) },
        gpid: cur.tgid.load(Ordering::Acquire),
        vtid: if vtid != 0 { vtid } else { cur.tid },
        gtid: cur.tid,
        uid: cur.creds.ruid.load(Ordering::Acquire),
        gid: cur.creds.rgid.load(Ordering::Acquire),
        dumpable: cur.dumpable.load(Ordering::Acquire) as i32,
        time_secs: (timekeeper::realtime_ns() / NS_PER_SEC) as i64,
        hostname: procfs::hooks::hostname(),
        comm: cur.comm().as_bytes().to_vec(),
        exe,
        rlimit_core: core_soft,
        cpu: current_cpu(),
    }
}

fn current_cpu() -> u32 {
    use hal::CpuOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86CpuOps::current_cpu() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmCpuOps::current_cpu() }
}
