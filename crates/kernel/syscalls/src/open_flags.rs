//! `open(2)` / `openat(2)` / `openat2(2)` flag word: the `O_*` bit names and
//! the pre-resolution normalisation ladder both entry points run before any
//! path is touched.
//!
//! Ungated on purpose. The slot file that consumes this is kernel-gated, so a
//! `#[cfg(test)]` block placed beside it would compile out silently and never
//! run (`docs/53`, CLAUDE.md phantom-test rule). Every rule below is observable
//! only as an errno or an errno ORDER, which is exactly the class that needs a
//! hosted check.

use syscall::errno::Errno;

pub const O_CREAT:     u32 = 0o100;
/// `O_EXCL` (asm-generic, both arches): with `O_CREAT`, an existing final
/// component → `EEXIST`.
pub const O_EXCL:      u32 = 0o200;
pub const O_TRUNC:     u32 = 0o1000;
pub const O_APPEND:    u32 = 0o2000;
pub const O_DIRECTORY: u32 = 0o200000;
// O_* flag VALUES are arch-specific (per-arch fcntl UAPI overrides):
// x86_64 = asm-generic (O_NOFOLLOW=0o400000); aarch64 uses the arm override
// (O_NOFOLLOW=0o100000, while 0x20000 is O_LARGEFILE which musl-aarch64 sets).
#[cfg(not(target_arch = "aarch64"))]
pub const O_NOFOLLOW:  u32 = 0o400000;
#[cfg(target_arch = "aarch64")]
pub const O_NOFOLLOW:  u32 = 0o100000;
/// `__O_TMPFILE` (full `O_TMPFILE` = this | `O_DIRECTORY`).
pub const O_TMPFILE:   u32 = 0o20000000;
/// `O_PATH` (asm-generic, both arches): an fd-reference open with no read/write
/// access — bypasses the access-mode permission check.
pub const O_PATH:      u32 = 0o10000000;
pub const O_CLOEXEC:   u32 = 0o2000000;
/// `O_ACCMODE` mask + the writable access modes.
pub const O_ACCMODE:   u32 = 0o3;
pub const O_RDONLY:    u32 = 0o0;
pub const O_WRONLY:    u32 = 0o1;
pub const O_RDWR:      u32 = 0o2;
/// `O_NONBLOCK` (asm-generic, both arches): a non-blocking conflicting open
/// fails the lease-break with `EWOULDBLOCK` instead of waiting.
pub const O_NONBLOCK:  u32 = 0o4000;
pub const O_NOCTTY:    u64 = 0o400;
pub const O_DSYNC:     u64 = 0o10000;
pub const O_ASYNC:     u64 = 0o20000;
pub const O_DIRECT:    u64 = 0o40000;
pub const O_LARGEFILE: u64 = 0o100000;
/// `O_NOATIME`: suppress the access-time update on every read through the
/// resulting description. Owner-only; the gate is in the open permission ladder.
pub const O_NOATIME:   u64 = 0o1000000;
pub const __O_SYNC:    u64 = 0o4000000;
pub const O_SYNC:      u64 = 0o4010000;
pub const O_EMPTYPATH: u64 = 0o400000000;
/// `OPENAT2_REGULAR`: openat2-only, lives in the upper 32 bits so it cannot
/// alias any `open(2)` flag. Requires the final component be a regular file.
pub const OPENAT2_REGULAR: u64 = 0o40000000000;

/// Mode bits an open may request (`S_IALLUGO`).
pub const S_IALLUGO: u64 = 0o7777;

pub const VALID_OPEN_FLAGS: u64 = O_CREAT as u64 | O_EXCL as u64 | O_TRUNC as u64
    | O_APPEND as u64
    | O_DIRECTORY as u64 | O_NOFOLLOW as u64 | O_TMPFILE as u64 | O_PATH as u64
    | O_CLOEXEC as u64 | O_ACCMODE as u64 | O_NONBLOCK as u64 | O_NOCTTY
    | O_DSYNC | O_ASYNC | O_DIRECT | O_LARGEFILE | O_NOATIME | O_SYNC | O_EMPTYPATH;
pub const VALID_OPENAT2_FLAGS: u64 = VALID_OPEN_FLAGS | OPENAT2_REGULAR;
/// The only flags an `O_PATH` open may carry alongside `O_PATH`.
pub const O_PATH_FLAGS: u64 = O_DIRECTORY as u64 | O_NOFOLLOW as u64 | O_PATH as u64
    | O_CLOEXEC as u64 | O_EMPTYPATH;

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// Normalise and validate the open flag/mode pair before any path mutation.
///
/// The two entry points differ ONLY in strictness, and that difference is the
/// whole reason this is one function: the legacy `open`/`openat` numbers were
/// shipped before unknown bits were rejected, so they silently mask unsupported
/// bits, silently drop every non-path flag beside `O_PATH`, and silently ignore
/// a mode passed without a creating flag. `openat2` was introduced with a
/// strictly-validated argument struct, so each of those three is `EINVAL`
/// instead. Everything AFTER that split is shared, in this order:
///
/// 1. `O_DIRECTORY | O_CREAT` → `EINVAL` (which also guards the `O_TMPFILE`
///    rung below, since `O_TMPFILE` requires `O_DIRECTORY` to be raised).
/// 2. `O_TMPFILE` without `O_DIRECTORY`, or with a non-writable access mode →
///    `EINVAL`.
/// 3. `O_DIRECTORY | OPENAT2_REGULAR` → `EINVAL` (contradictory type demands).
/// 4. `__O_SYNC` folds `O_DSYNC` in, so every caller that only tests `O_DSYNC`
///    sees the sync request.
///
/// Returns the normalised `(flags, mode)` truncated to 32 bits, or a negative
/// errno. # C: O(1)
pub fn normalize_open_flags(flags: u64, mode: u64, openat2: bool) -> Result<(u32, u32), i64> {
    let mut f = flags;
    let mut m = mode;
    if !openat2 {
        f &= VALID_OPEN_FLAGS;
        m &= S_IALLUGO;
        if (f & O_PATH as u64) != 0 { f &= O_PATH_FLAGS; }
        if (f & (O_CREAT as u64 | O_TMPFILE as u64)) == 0 { m = 0; }
    } else {
        if (f & !VALID_OPENAT2_FLAGS) != 0 { return Err(einval()); }
        if (f & (O_CREAT as u64 | O_TMPFILE as u64)) != 0 {
            if (m & !S_IALLUGO) != 0 { return Err(einval()); }
        } else if m != 0 {
            return Err(einval());
        }
        if (f & O_PATH as u64) != 0 && (f & !O_PATH_FLAGS) != 0 { return Err(einval()); }
    }
    if (f & (O_DIRECTORY as u64 | O_CREAT as u64)) == (O_DIRECTORY as u64 | O_CREAT as u64) {
        return Err(einval());
    }
    if (f & O_TMPFILE as u64) != 0 {
        if (f & O_DIRECTORY as u64) == 0 { return Err(einval()); }
        let acc = (f as u32) & O_ACCMODE;
        if acc != O_WRONLY && acc != O_RDWR { return Err(einval()); }
    }
    if (f & (O_DIRECTORY as u64 | OPENAT2_REGULAR)) == (O_DIRECTORY as u64 | OPENAT2_REGULAR) {
        return Err(einval());
    }
    if (f & __O_SYNC) != 0 { f |= O_DSYNC; }
    Ok((f as u32, m as u32))
}

/// Whether an open must take mount write admission (`EROFS`) BEFORE the
/// permission ladder runs, rather than after it.
///
/// Exactly one case does: truncating a regular file. The truncate is performed
/// as part of the open, so a read-only mount cannot host the open at all and
/// says so first — whatever the caller's permissions are.
///
/// Every OTHER write-intent open takes its admission AFTER the permission
/// ladder, which is what makes `open(path, O_WRONLY)` of an unwritable file on
/// a read-only mount report `EACCES`: the caller is told the reason that would
/// still stand if the mount were remounted read-write.
///
/// A CREATED file never truncates (there is nothing yet to truncate), and a
/// special file ignores `O_TRUNC` outright because its open addresses a driver
/// rather than filesystem data — a read-only bind mount of /dev must not stop a
/// sandboxed service opening a device node for logging. # C: O(1)
pub fn trunc_needs_mount_write(flags: u32, ftype: vfs::types::FileType, created: bool) -> bool {
    (flags & O_TRUNC) != 0
        && !created
        && matches!(ftype, vfs::types::FileType::Regular)
}

/// The `may_open` flag rungs decoded out of a normalised open flag word, so the
/// arch-specific numeric `O_*` values stop at this boundary. `created` reports
/// an open that CREATED the file: such an open never truncates, because there
/// is nothing yet to truncate. # C: O(1)
pub fn open_intent(flags: u32, created: bool) -> vfs::namei::OpenIntent {
    let acc = flags & O_ACCMODE;
    vfs::namei::OpenIntent {
        write_mode: acc != O_RDONLY,
        append:     (flags & O_APPEND) != 0,
        trunc:      (flags & O_TRUNC) != 0 && !created,
        noatime:    (flags as u64 & O_NOATIME) != 0,
    }
}
