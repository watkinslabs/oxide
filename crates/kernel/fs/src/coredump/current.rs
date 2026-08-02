// Snapshot the dying process and send its dump wherever the pattern says.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::dumpable::{dump_allowed, suid_safe_required};
use super::pattern::{self, CoreContext, CoreKind};

/// Nanoseconds per second, for the wall-clock stamp a pattern can interpolate.
const NS_PER_SEC: u64 = 1_000_000_000;

/// Granularity `RLIMIT_CORE` truncates on. Linux emits the memory half of a
/// dump one page at a time (`dump_user_range`), so the limit binds at a page
/// boundary rather than mid-page.
const DUMP_CHUNK: usize = hal::PAGE_SIZE_BYTES as usize;

/// Dump the running process, killed by `signo`.
///
/// `regs` is the thread's live kernel-entry frame, threaded in from the return
/// path that is about to tear the process down — the registers a debugger reads
/// as the crash site come from there and from nowhere else. `payload` is the
/// killing signal's descriptor, which becomes the dump's `NT_SIGINFO`.
///
/// Best-effort: the process is already terminating, so a failure to deliver the
/// dump cannot be reported to anyone. It is never papered over as success —
/// a pattern naming a program that does not exist produces no dump and no file.
/// # SAFETY: `regs` is the calling thread's live entry frame, or null.
/// # C: O(dump size)
pub unsafe fn write_for_current(signo: i32, regs: *const crate::sig_dispatch::UserRegs,
                                payload: Option<hal::SigPayload>) {
    let Some(cur) = sched::live::current() else { return };
    let cx = snapshot(&cur, signo);
    // Linux `coredump_skip`: `cprm->dumpable == TASK_DUMPABLE_OFF` produces NO
    // dump at all, by any destination. This is the whole point of
    // `prctl(PR_SET_DUMPABLE, 0)` — a daemon holding key material asks not to
    // have its address space written anywhere — and it is also the state a
    // credential change drops a setuid process into. Snapshotting the flag
    // only to interpolate `%d` into the filename, as this did, meant a
    // process that asked not to be dumped got a full memory image on its
    // first SIGSEGV, and a setuid binary's dump was readable to whoever owned
    // the pattern's directory.
    if !dump_allowed(cx.dumpable) { return; }
    let raw = pattern::core_pattern();
    let kind = pattern::kind_of(trim(&raw));
    // `coredump_force_suid_safe`: a dump whose dumpability was downgraded by a
    // privilege change (`SUID_DUMP_ROOT`) may only go to a fully qualified
    // path. A relative pattern resolves against the dying process's own cwd,
    // which an unprivileged caller controls, so honouring it would let that
    // caller choose where a root-owned memory image lands.
    if kind == CoreKind::File && suid_safe_required(cx.dumpable)
        && !pattern::file_path(&raw, &cx).starts_with('/') { return; }

    // A program collects the dump itself and is not subject to the size limit —
    // nothing is written to a filesystem, and Linux overwrites `cprm->limit`
    // with RLIM_INFINITY once the helper is chosen. A file destination is
    // bounded: a zero limit is how a system says it does not want core files.
    if kind == CoreKind::File && !sched::rlimit::dump::file_dump_enabled(cx.rlimit_core) { return; }

    // Linux latches `mm->core_state` for the whole dump: a reaper that stole
    // the address space mid-write would leave the image describing memory that
    // no longer exists. `process_mrelease` reads the same flag and refuses.
    // SAFETY: `cur` is the running task, so its mm slot cannot be replaced under us; the flag is the only field touched.
    if let Some(mm) = unsafe { cur.mm_ref() } { mm.set_coredumping(true); }
    // SAFETY: caller's contract — `regs` is this thread's live entry frame, and the address space it describes is still this task's own.
    let body = unsafe { super::capture::build_image(&cx, regs, payload) };
    match kind {
        CoreKind::Pipe => { super::pipe::dump_to_program(trim(&raw), &cx, &body); }
        // Linux `dump_emit` refuses the first chunk that would cross the limit,
        // so an over-limit dump is TRUNCATED rather than dropped — a partial
        // core is still worth having, and gdb reads it.
        CoreKind::File => {
            let n = sched::rlimit::dump::prefix_len(body.len(), cx.rlimit_core, DUMP_CHUNK);
            super::file_target::write_to_file(&pattern::file_path(&raw, &cx), &body[..n],
                cx.uid, cx.gid, suid_safe_required(cx.dumpable));
        }
        // A socket destination needs a connection to a listener that this
        // kernel has no path to yet, so nothing is delivered. Writing a file
        // instead would put the dump somewhere the operator did not ask for.
        CoreKind::Socket => {}
    }
    // SAFETY: same running-task mm access as the latch above.
    if let Some(mm) = unsafe { cur.mm_ref() } { mm.set_coredumping(false); }
}

fn trim(p: &[u8]) -> &[u8] {
    let mut end = p.len();
    while end > 0 && (p[end - 1] == b'\n' || p[end - 1] == b'\r') { end -= 1; }
    &p[..end]
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
