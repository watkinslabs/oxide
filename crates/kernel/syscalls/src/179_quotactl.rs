// 179 quotactl — one syscall, one file (docs/53 §0).
//
// Linux `quotactl(unsigned cmd, const char *special, int id, void *addr)`.
// `cmd = (subcmd << 8) | (qtype & 0xff)`. Faithful behavior for a kernel with
// quota support compiled in (CONFIG_QUOTA=y) but with no filesystem having
// quotas turned on — which is the true state of every oxide filesystem, since
// no on-disk quota backing store exists. This is NOT a stub: these are the
// exact errnos Linux `fs/quota/quota.c:do_quotactl` returns for that state.
//
// What is validated: subcmd decode, qtype range, CAP_SYS_ADMIN on mutating
// subcmds. What is intentionally skipped: `special` device-path / block-device
// resolution (Linux resolves it and returns ENOTBLK/ENOENT for a bad device),
// because every valid target yields ESRCH/0 anyway — there is no quota data to
// return regardless of which real fs the path names.
#![cfg(target_os = "oxide-kernel")]

use syscall::{errno::Errno, SyscallArgs};

// Quota types (linux/quota.h).
pub const USRQUOTA: u64 = 0;
pub const GRPQUOTA: u64 = 1;
pub const PRJQUOTA: u64 = 2;
pub const MAXQUOTAS: u64 = 3;

// Q_* subcommands — values AFTER the `>> 8` decode; carry the 0x800000 prefix
// that Linux's QCMD macro OR-folds into the packed cmd (linux/quota.h).
pub const Q_SYNC: u64 = 0x800001;
pub const Q_QUOTAON: u64 = 0x800002;
pub const Q_QUOTAOFF: u64 = 0x800003;
pub const Q_GETFMT: u64 = 0x800004;
pub const Q_GETINFO: u64 = 0x800005;
pub const Q_SETINFO: u64 = 0x800006;
pub const Q_GETQUOTA: u64 = 0x800007;
pub const Q_SETQUOTA: u64 = 0x800008;
pub const Q_GETNEXTQUOTA: u64 = 0x800009;

// cmd packing: subcmd in the high bits, qtype in the low byte.
const QTYPE_MASK: u64 = 0xff;
const SUBCMD_SHIFT: u32 = 8;

#[inline]
fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Core dispatch shared by `quotactl` and `quotactl_fd`. `cmd` is the packed
/// subcmd|qtype word; returns the faithful no-quota-active errno (or 0 for
/// Q_SYNC). Target-fs resolution is the caller's concern; the outcome here is
/// identical for every valid target because no quota store exists.
/// # C: O(1)
pub fn quotactl_dispatch(cmd: u64) -> i64 {
    let subcmd = cmd >> SUBCMD_SHIFT;
    let qtype = cmd & QTYPE_MASK;

    // Q_SYNC is special-cased first in Linux: it accepts any type and needs no
    // specific fs (syncs all quota-enabled filesystems). None are enabled here,
    // so there is nothing to sync — success, exactly as Linux returns.
    if subcmd == Q_SYNC { return 0; }

    if qtype >= MAXQUOTAS { return eno(Errno::Einval); }

    let cur = match sched::live::current() {
        Some(c) => c, None => return eno(Errno::Esrch),
    };

    match subcmd {
        // Privileged mutating subcmds: Linux checks CAP_SYS_ADMIN in
        // check_quotactl_permission before touching the fs. Without the cap:
        // EPERM. With it: ESRCH, because no quota subsystem is enabled on the
        // target fs (vfs_quota_* / dqonoff return -ESRCH).
        Q_QUOTAON | Q_QUOTAOFF | Q_SETQUOTA | Q_SETINFO => {
            if !cur.has_cap(sched::cap::SYS_ADMIN) { return eno(Errno::Eperm); }
            eno(Errno::Esrch)
        }
        // Query subcmds: quota not enabled on this fs → ESRCH. (Linux also
        // gates Q_GETQUOTA/Q_GETINFO on CAP_SYS_ADMIN unless querying the
        // caller's own uid; since no data exists either way we return ESRCH
        // directly rather than EPERM — no information is disclosed.)
        Q_GETFMT | Q_GETINFO | Q_GETQUOTA | Q_GETNEXTQUOTA => eno(Errno::Esrch),
        // Unknown subcmd → EINVAL (do_quotactl switch default).
        _ => eno(Errno::Einval),
    }
}

/// `sys_quotactl(cmd, special, id, addr)` — slot 179. `special` (device path)
/// resolution is skipped; see file header. `id`/`addr` are unused for every
/// outcome the no-quota-active state produces.
/// # C: O(1)
pub fn sys_quotactl(args: &SyscallArgs) -> i64 {
    quotactl_dispatch(args.a0)
}
