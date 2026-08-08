// Bind the pure execve credential decision (`crate::exec_creds`) to live
// kernel state: read the task's credentials, the exec'd file's mode/owner, its
// mount's `nosuid` flag, its `security.capability` xattr and the caller's user
// namespace; decide; then commit the result to the one owner of each field.
//
// The decision itself lives in `exec_creds` — ungated and unit-tested. Nothing
// here may branch on privilege; this file only gathers and stores.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use nscg::user_ns::{self, IdMapKind};
use syscall::errno::Errno;

use crate::exec_creds::{self, ExecContext, ExecTransition, FileCaps, TaskCreds};

/// Linux `prepare_creds`: `bprm->cred` starts as a copy of `current_cred()`.
/// # C: O(1)
fn snapshot_creds(cur: &sched::Task) -> TaskCreds {
    let c = &cur.creds;
    TaskCreds {
        ruid: c.ruid.load(Ordering::Acquire), euid: c.euid.load(Ordering::Acquire),
        suid: c.suid.load(Ordering::Acquire), fsuid: c.fsuid.load(Ordering::Acquire),
        rgid: c.rgid.load(Ordering::Acquire), egid: c.egid.load(Ordering::Acquire),
        sgid: c.sgid.load(Ordering::Acquire), fsgid: c.fsgid.load(Ordering::Acquire),
        cap_permitted:   c.cap_permitted.load(Ordering::Acquire),
        cap_effective:   c.cap_effective.load(Ordering::Acquire),
        cap_inheritable: c.cap_inheritable.load(Ordering::Acquire),
        cap_ambient:     c.cap_ambient.load(Ordering::Acquire),
        cap_bounding:    c.cap_bounding.load(Ordering::Acquire),
        securebits:      c.securebits.load(Ordering::Acquire),
    }
}

/// Linux `get_vfs_caps_from_disk`: read `security.capability` off the inode.
/// An absent, oversized or malformed value is "no file capabilities", exactly
/// as `-ENODATA` / `-EINVAL` are treated by `get_file_caps`.
/// # C: O(1)
fn read_file_caps(inode: &vfs::InodeRef) -> FileCaps {
    /// `XATTR_CAPS_SZ` — the revision-3 `struct vfs_ns_cap_data`, the largest
    /// value the kernel will read.
    const XATTR_CAPS_SZ: usize = 24;
    const NAME: &str = "security.capability";
    let want = ::fs::xattr::query_len(inode, NAME);
    if want == 0 || want > XATTR_CAPS_SZ { return FileCaps::default(); }
    let mut buf = [0u8; XATTR_CAPS_SZ];
    if !::fs::xattr::query_into(inode, NAME, &mut buf[..want]) { return FileCaps::default(); }
    exec_creds::decode_file_caps(&buf[..want]).unwrap_or_default()
}

/// Linux `ptracer_capable(current, new->user_ns)`. TRUE when no tracer is
/// attached ("An absent tracer adds no restrictions").
///
/// Linux consults `tsk->ptracer_cred`, the tracer's credentials CAPTURED at
/// attach; this tree keeps only the tracer's tid, so the tracer's LIVE
/// effective set is what gets tested. The two differ only if the tracer drops
/// CAP_SYS_PTRACE after attaching, in which case this is the stricter reading.
/// # C: O(1)
fn ptracer_capable(cur: &sched::Task) -> bool {
    let tracer = cur.traced_by.load(Ordering::Acquire);
    if tracer == 0 { return true; }
    match sched::live::registry::lookup(tracer) {
        Some(t) => t.creds.has_cap(sched::cap::SYS_PTRACE),
        None => true,
    }
}

/// Gather the live inputs and run the transition.
///
/// `file` is `None` for the early-boot path where the image came from the raw
/// rootfs reader with no mounted inode behind it: no inode means no setuid
/// bits, no file capabilities and no `mnt_may_suid`, which is the safe reading
/// and matches what an unresolvable `bprm->file` would do.
/// # C: O(ngroups + extents)
pub(crate) fn decide(cur: &sched::Task, file: Option<&vfs::VfsPath>)
    -> Result<ExecTransition, Errno>
{
    let old = snapshot_creds(cur);
    let user_map = cur.namespace_owner(namespace_identity::NamespaceKind::User)
        .and_then(|owner| user_ns::snapshot_map(&owner, IdMapKind::Uid).ok())
        .unwrap_or_default();
    let gid_map = cur.namespace_owner(namespace_identity::NamespaceKind::User)
        .and_then(|owner| user_ns::snapshot_map(&owner, IdMapKind::Gid).ok())
        .unwrap_or_default();
    // `make_kuid(new->user_ns, 0)`. An unmapped namespace root is Linux's
    // INVALID_UID, which no real uid can equal — so the privileged-root path
    // is closed rather than aliased onto the overflow id.
    let root_uid = user_ns::to_host_checked(&user_map, 0).unwrap_or(u32::MAX);

    let (file_mode, file_uid, file_gid, mnt_may_suid, may_exec, not_readable, file_caps) =
        match file {
            // `not_readable = false`: the fallback only fires for the boot
            // image read raw by the root task that has not mounted a root
            // filesystem yet, which can read it. Claiming otherwise would make
            // PID 1 non-dumpable on a technicality Linux never faces — there is
            // always a `bprm->file` for `would_dump` to test.
            None => (0u16, 0u32, 0u32, false, false, false, FileCaps::default()),
            Some(vp) => {
                let idmap = vfs::mount::idmap_for(vp.mnt_id);
                let mode = vp.inode.perm().unwrap_or(0);
                let vfsuid = idmap.map_out_uid(vp.inode.uid().unwrap_or(0));
                let vfsgid = idmap.map_out_gid(vp.inode.gid().unwrap_or(0));
                let may_suid = vfs::mount::mount_by_id(vp.mnt_id)
                    .map(|m| m.may_suid()).unwrap_or(false);
                let cred = crate::pathresolve::current_cred();
                // Linux re-runs both tests on the final `bprm->file`:
                // `bprm_fill_uid` needs MAY_EXEC under `inode_lock`, and
                // `would_dump` needs MAY_READ to decide dumpability.
                let may_exec = vfs::inode_permission(&vp.inode, vfs::MAY_EXEC, &cred).is_ok();
                let unreadable = vfs::inode_permission(&vp.inode, vfs::MAY_READ, &cred).is_err();
                (mode, vfsuid, vfsgid, may_suid, may_exec, unreadable, read_file_caps(&vp.inode))
            }
        };

    let groups = cur.creds.group_list();
    let groups: &[u32] = groups.as_deref().unwrap_or(&[]);
    let cx = ExecContext {
        old,
        file_mode, file_uid, file_gid,
        mnt_may_suid,
        // `vfsuid_has_mapping(bprm->cred->user_ns, vfsuid)`.
        file_uid_mapped: user_ns::has_mapping(&user_map, file_uid),
        file_gid_mapped: user_ns::has_mapping(&gid_map, file_gid),
        may_exec,
        // `vfsuid_root_in_currentns`: the xattr's rootid must be uid 0 here.
        file_caps_rootid_is_root: user_ns::has_mapping(&user_map, file_caps.rootid)
            && user_ns::to_ns(&user_map, file_caps.rootid, user_ns::OverflowId::Uid) == 0,
        file_caps,
        no_new_privs: cur.no_new_privs.load(Ordering::Acquire),
        fs_shared: cur.fs_context_shared_outside_thread_group(),
        ptracer_capable: ptracer_capable(cur),
        can_setuid: old.cap_effective & (1u64 << sched::cap::SETUID) != 0,
        root_uid,
        groups,
        not_readable,
        suid_dumpable: sched::cred::suid_dumpable(),
    };
    exec_creds::transition(&cx)
}

/// Install the decided credentials. Called AFTER the point of no return, so it
/// cannot fail — Linux commits in `begin_new_exec` for the same reason.
/// # C: O(1)
pub(crate) fn commit(cur: &sched::Task, t: &ExecTransition) {
    let c = &cur.creds;
    let n = &t.new;
    c.euid.store(n.euid, Ordering::Release);
    c.suid.store(n.suid, Ordering::Release);
    c.fsuid.store(n.fsuid, Ordering::Release);
    c.egid.store(n.egid, Ordering::Release);
    c.sgid.store(n.sgid, Ordering::Release);
    c.fsgid.store(n.fsgid, Ordering::Release);
    c.cap_permitted.store(n.cap_permitted, Ordering::Release);
    c.cap_effective.store(n.cap_effective, Ordering::Release);
    c.cap_inheritable.store(n.cap_inheritable, Ordering::Release);
    c.cap_ambient.store(n.cap_ambient, Ordering::Release);
    c.securebits.store(n.securebits, Ordering::Release);
    // `me->personality &= ~bprm->per_clear` — a privileged image never inherits
    // ADDR_NO_RANDOMIZE / READ_IMPLIES_EXEC / MMAP_PAGE_ZERO / ADDR_COMPAT_LAYOUT
    // that the caller pre-armed.
    sched::personality::clear(cur, t.per_clear);
    // `SET_PERSONALITY2(*elf_ex, &arch_state)` — the arch half, which on both
    // 64-bit targets clears READ_IMPLIES_EXEC unconditionally.
    crate::exec_persona::set_personality(cur);
    // `arch_setup_new_exec()` + `reset_thread_features()` — the arch state
    // `arch_prctl` owns (CPUID faulting, CET facility set), which a new image
    // must not inherit.
    crate::exec_persona::arch_setup_new_exec(cur);
    // Linux `flush_thread()` + `arch_setup_new_exec()`: the per-thread ARCH
    // flags whose exec rule is architecture-specific (TSC trap, tagged-address
    // ABI). Owned by sched so the two arches cannot drift apart here.
    sched::exec_flush::flush_thread_flags(cur);
    cur.dumpable.store(t.dumpable, Ordering::Release);
    // Landlock's `bprm_creds_prepare`: the layer set this EXECUTION enforced
    // is empty for a program that has just replaced the one that enforced it,
    // so its denials fall under the new-execution reporting rule rather than
    // the same-execution one. The subdomain switch survives — it was a
    // decision about the layers, not about the program that made it.
    let ll = cur.landlock_log_state.load(Ordering::Acquire);
    cur.landlock_log_state.store(::landlock::logging::state_after_exec(ll), Ordering::Release);
    // Linux `prepare_exec_creds`: the new image gets no thread keyring and a
    // fresh (absent) process keyring; the session keyring and any assumed
    // instantiation authority are inherited. Dropping the first two is what
    // stops a key the pre-exec program left behind from being visible across a
    // setuid exec, so it belongs at the credential commit — the same point the
    // euid/fsuid/capability transition above lands.
    fs::keyring::exec_keys(cur.tid, cur.vtgid.load(Ordering::Acquire));
}

/// Draw this exec's address randomisation (`aslr::ExecRnd`).
///
/// Linux applies `me->personality &= ~bprm->per_clear` inside `begin_new_exec`,
/// which runs BEFORE `load_elf_binary` derives `PF_RANDOMIZE`.
/// This kernel commits credentials later — past the
/// point of no return — so `per_clear` has to be folded in here by hand.
/// Reading the raw persona instead would let a caller pre-arm
/// `ADDR_NO_RANDOMIZE`, exec a setuid binary and have it run at fixed
/// addresses: precisely the escalation `PER_CLEAR_ON_SETID` exists to stop.
/// # C: O(1) — five CRNG words
pub(crate) fn exec_rnd(cur: &sched::Task, per_clear: u32) -> aslr::ExecRnd {
    let persona = sched::personality::get(cur) & !per_clear;
    aslr::ExecRnd::draw(persona & sched::personality::ADDR_NO_RANDOMIZE != 0)
}

/// Linux `setup_new_exec` → `arch_pick_mmap_layout(mm, &rlim_stack)`: this
/// exec's arena anchor AND search direction.
///
/// `raw_stack_rlim` is the caller's `RLIMIT_STACK` soft limit BEFORE this
/// kernel's `min(…, RLIM_STACK_MAP_CAP)` clamp, because `RLIM_INFINITY` is one
/// of the three conditions that select the legacy layout and the clamp would
/// erase it. `per_clear` is folded in for the same reason `exec_rnd` folds it:
/// a caller must not pre-arm `ADDR_COMPAT_LAYOUT` and have a setuid image
/// inherit a predictable low arena.
/// # C: O(1)
pub(crate) fn exec_mmap_layout(cur: &sched::Task, per_clear: u32, rnd: &aslr::ExecRnd,
                               rlim_stack: u64, raw_stack_rlim: u64) -> aslr::Layout {
    let persona = sched::personality::at_exec(sched::personality::get(cur), per_clear);
    rnd.mmap_layout(rlim_stack,
                    sched::personality::addr_compat_layout(persona),
                    raw_stack_rlim == sched::rlimit::INFINITY)
}

/// Linux `begin_new_exec`: a secure exec resets `RLIMIT_STACK` to `_STK_LIM`
/// so a hostile caller cannot hand a setuid binary a pathological stack limit.
/// # C: O(1)
pub(crate) fn secure_stack_limit(rlim_stack: u64, secure_exec: bool) -> u64 {
    /// Linux `_STK_LIM` — 8 MiB.
    const STK_LIM: u64 = 8 * 1024 * 1024;
    if secure_exec && rlim_stack > STK_LIM { STK_LIM } else { rlim_stack }
}
