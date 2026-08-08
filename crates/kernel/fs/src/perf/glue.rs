// Live-kernel glue: fetch the user `perf_event_attr`, gather the credentials
// the pure ladders need, install the fd, and route ioctls.

use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use vfs::{File, OpenFlags};

use super::attr::{parse_attr, AttrErr};
use super::event::{now_ns, PerfEvent};
use super::file::{event_of, is_perf_inode, make_perf_event_inode};
use super::ioctl::{apply_state, classify, period_result, refresh_result, PerfIoctl};
use super::open::{admit, GroupCtx, OpenCtx};
use super::uapi::{attr_bit, attr_off, attr_size, ioc};
use super::uapi;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `perf_event_open(attr, pid, cpu, group_fd, flags)` — slot 298. # C: O(1)
pub fn sys_perf_event_open(args: &syscall::SyscallArgs) -> i64 {
    let uattr    = args.a0;
    let pid      = args.a1 as i32;
    let cpu      = args.a2 as i32;
    let group_fd = args.a3 as i32;
    let flags    = args.a4;

    // `flags & ~PERF_FLAG_ALL` is checked before the attr copy.
    if flags & !uapi::open_flags::ALL != 0 { return err(Errno::Einval); }

    // `perf_copy_attr`: `get_user(size, &uattr->size)` first, then the
    // size-bounded `copy_struct_from_user`.
    let mut size_buf = [0u8; 4];
    if uaccess::copy_from_user(&mut size_buf, uattr + attr_off::SIZE as u64).is_err() {
        return err(Errno::Efault);
    }
    let raw_size = u32::from_le_bytes(size_buf);
    let size = if raw_size == 0 { attr_size::VER0 } else { raw_size };
    if size < attr_size::VER0 || size > attr_size::CEILING { return e2big(uattr); }
    let mut raw = vec![0u8; size as usize];
    if uaccess::copy_from_user(&mut raw, uattr).is_err() { return err(Errno::Efault); }

    let cur = match sched::current() { Some(c) => c, None => return err(Errno::Esrch) };
    let perfmon = cur.has_cap(sched::cap::PERFMON) || cur.has_cap(sched::cap::SYS_ADMIN);
    let paranoid = sched::perf_sw::paranoid();
    let attr = match parse_attr(&raw, raw_size, paranoid, perfmon) {
        Ok(a)                     => a,
        Err(AttrErr::TooBig)      => return e2big(uattr),
        Err(e)                    => return err(e.errno()),
    };

    // `group_fd != -1` → `is_perf_file()` then the leader's private_data.
    // SAFETY: borrows the CURRENT task's own fd-table slot, which only that
    // task replaces, and it is here inside its own perf_event_open — so no
    // competing mutator; the Arc is cloned out before the borrow ends.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return err(Errno::Ebadf) };
    let leader = if group_fd == -1 { None } else {
        match fdt.get(group_fd).ok().and_then(|f| {
            if is_perf_inode(&f.inode()) { event_of(&f.inode()) } else { None }
        }) {
            Some(l) => Some(l),
            None    => return err(Errno::Ebadf),
        }
    };

    // `find_lively_task_by_vpid(pid)`; `pid == 0` means the caller.
    let target = if pid == -1 { None }
        else if pid == 0 { sched::registry::lookup(cur.tid) }
        else { sched::registry::lookup_by_vpid(pid as u32) };

    let ctx = OpenCtx {
        paranoid, perfmon,
        cap_kill: cur.has_cap(sched::cap::KILL),
        nr_cpus:  cpu::count().max(1),
        task_found: pid == -1 || target.is_some(),
        may_access: target.as_ref().is_some_and(|t| sched::ptrace_access::may_access(cur, t).is_ok()),
        group: leader.as_ref().map(|l| GroupCtx {
            leader_inherit:    l.attr.bit(attr_bit::INHERIT),
            leader_is_sibling: l.leader.is_some(),
            leader_tid:        l.tid,
            leader_cpu:        l.cpu,
        }),
    };
    let ok = match admit(&attr, pid, cpu, group_fd, flags, &ctx) { Ok(o) => o, Err(e) => return err(e) };

    let tid = target.as_ref().map(|t| t.tid);
    let leader_ref = if ok.join_group { leader.clone().map(|l| Arc::downgrade(&l)) } else { None };
    let ev = PerfEvent::new(attr, ok.source, tid, cpu, leader_ref);
    if ok.join_group {
        if let Some(l) = leader.as_ref() { l.state.lock().siblings.push(Arc::downgrade(&ev)); }
    }

    let inode = make_perf_event_inode(ev);
    let dentry = vfs::dcache::d_alloc_pseudo("[perf_event]", inode.clone(), &crate::anon_dname::ANON_INODE_OPS);
    let mut f = OpenFlags::O_RDWR;
    if ok.cloexec { f |= OpenFlags::O_CLOEXEC; }
    let file = File::new(inode, dentry, f);
    match fdt.install_limit(file, f, cur.nofile_soft()) { Ok(fd) => fd as i64, Err(e) => -(e as i64) }
}

/// `err_size:` — Linux writes `sizeof(struct perf_event_attr)` back into
/// `uattr->size` so userspace can retry with the kernel's size.
fn e2big(uattr: u64) -> i64 {
    let _ = uaccess::copy_to_user(uattr + attr_off::SIZE as u64, &attr_size::CURRENT.to_le_bytes());
    err(Errno::E2big)
}

/// `perf_ioctl` — routed from the generic ioctl dispatcher. # C: O(group)
pub fn handle_perf_ioctl(inode: &vfs::InodeRef, req: u64, arg: u64) -> i64 {
    let ev = match event_of(inode) { Some(e) => e, None => return err(Errno::Enotty) };
    let what = match classify(req) { Some(w) => w, None => return err(Errno::Enotty) };
    let group_wide = arg & ioc::FLAG_GROUP != 0;
    match what {
        PerfIoctl::Enable | PerfIoctl::Disable | PerfIoctl::Reset => {
            let members = if group_wide { ev.group_members() } else { vec![ev.clone()] };
            apply_state(&members, what);
            0
        }
        PerfIoctl::Refresh => {
            match refresh_result(ev.attr.bit(attr_bit::INHERIT), ev.attr.is_sampling()) {
                Err(e) => err(e),
                Ok(())  => { let src = ev.sample(); let now = now_ns();
                             ev.state.lock().counter.enable(src, now); 0 }
            }
        }
        PerfIoctl::Period => {
            let mut v = [0u8; 8];
            if uaccess::copy_from_user(&mut v, arg).is_err() { return err(Errno::Efault); }
            let value = u64::from_le_bytes(v);
            match period_result(ev.attr.is_sampling(), ev.attr.freq(), value, sched::perf_sw::sample_rate()) {
                Err(e) => err(e),
                Ok(())  => { ev.state.lock().period = value; 0 }
            }
        }
        PerfIoctl::Id => {
            if uaccess::copy_to_user(arg, &ev.id.to_le_bytes()).is_err() { return err(Errno::Efault); }
            0
        }
        PerfIoctl::SetOutput => {
            // Redirecting samples to another event's ring buffer. That buffer
            // is something oxide's software PMUs never allocate, so the only
            // reachable arm is `-EINVAL` for an event with no ring buffer,
            // plus `-EBADF` for a non-perf fd.
            if arg as i32 != -1 {
                let cur = match sched::current() { Some(c) => c, None => return err(Errno::Ebadf) };
                // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
                let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return err(Errno::Ebadf) };
                let ok = fdt.get(arg as i32).ok().is_some_and(|f| is_perf_inode(&f.inode()));
                if !ok { return err(Errno::Ebadf); }
            }
            err(Errno::Einval)
        }
        PerfIoctl::SetFilter => {
            // `strndup_user(arg, PAGE_SIZE)` first, then `-EINVAL` for an event
            // that is neither a tracepoint nor an address-filtering PMU.
            let mut probe = [0u8; 1];
            if uaccess::copy_from_user(&mut probe, arg).is_err() { return err(Errno::Efault); }
            err(Errno::Einval)
        }
        // `bpf_prog_get(arg)` on a kernel that loads no programs.
        PerfIoctl::SetBpf   => err(Errno::Ebadf),
        // `perf_event_query_prog_array` on an event with no attached programs.
        PerfIoctl::QueryBpf => err(Errno::Enoent),
        // `rb_toggle_paused` needs a mapped ring buffer.
        PerfIoctl::PauseOutput => err(Errno::Einval),
        PerfIoctl::ModifyAttributes => {
            let mut size_buf = [0u8; 4];
            if uaccess::copy_from_user(&mut size_buf, arg + attr_off::SIZE as u64).is_err() {
                return err(Errno::Efault);
            }
            let raw_size = u32::from_le_bytes(size_buf);
            let size = if raw_size == 0 { attr_size::VER0 } else { raw_size };
            if size < attr_size::VER0 || size > attr_size::CEILING { return e2big(arg); }
            let mut raw = vec![0u8; size as usize];
            if uaccess::copy_from_user(&mut raw, arg).is_err() { return err(Errno::Efault); }
            let cur = match sched::current() { Some(c) => c, None => return err(Errno::Esrch) };
            let perfmon = cur.has_cap(sched::cap::PERFMON) || cur.has_cap(sched::cap::SYS_ADMIN);
            let new = match parse_attr(&raw, raw_size, sched::perf_sw::paranoid(), perfmon) {
                Ok(a)                => a,
                Err(AttrErr::TooBig) => return e2big(arg),
                Err(e)               => return err(e.errno()),
            };
            // `perf_event_modify_attr`: only `PERF_TYPE_BREAKPOINT` events can
            // be modified; everything else is `-EOPNOTSUPP`, and a type change
            // is `-EINVAL`.
            if new.ty != ev.attr.ty { return err(Errno::Einval); }
            err(Errno::Eopnotsupp)
        }
    }
}

/// `/proc/<pid>/status` voluntary/nonvoluntary context-switch counters — the
/// same `Task` fields `PERF_COUNT_SW_CONTEXT_SWITCHES` reads. # C: O(1)
pub fn task_ctxt_switches(t: &sched::Task) -> (u64, u64) {
    (t.nvcsw.load(Ordering::Relaxed), t.nivcsw.load(Ordering::Relaxed))
}
