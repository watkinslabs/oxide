// `personality(2)` (slot 135) execution domain — UAPI bits plus the work fns
// its consumers call. Linux `include/uapi/linux/personality.h` +
// `kernel/exec_domain.c`.
//
// The persona is per-task, inherited by `fork`/`clone` (Linux
// `dup_task_struct` copies `task_struct::personality`) and preserved across
// `execve`. Bits are NOT decoration: `READ_IMPLIES_EXEC` is consulted by
// `mmap`/`mprotect` and `UNAME26` by `uname`, exactly as Linux does.

use core::sync::atomic::Ordering;

use crate::Task;

/// `uname(2)` reports a 2.6.x release. Linux `override_release`.
pub const UNAME26: u32 = 0x002_0000;
/// Disable address-space randomization for this process.
pub const ADDR_NO_RANDOMIZE: u32 = 0x004_0000;
/// Userspace function pointers are descriptors (FDPIC signal handling).
pub const FDPIC_FUNCPTRS: u32 = 0x008_0000;
/// `execve` maps a zero page at VA 0 for SVR4 bug emulation.
pub const MMAP_PAGE_ZERO: u32 = 0x010_0000;
/// Legacy mmap layout (bottom-up allocation from TASK_UNMAPPED_BASE).
pub const ADDR_COMPAT_LAYOUT: u32 = 0x020_0000;
/// `PROT_READ` implies `PROT_EXEC` for mmap/mprotect.
pub const READ_IMPLIES_EXEC: u32 = 0x040_0000;
/// Address space limited to 32 bits.
pub const ADDR_LIMIT_32BIT: u32 = 0x080_0000;
/// Report 32-bit inode numbers.
pub const SHORT_INODE: u32 = 0x100_0000;
/// Round timeouts to whole seconds.
pub const WHOLE_SECONDS: u32 = 0x200_0000;
/// Do not reload select/poll timeouts after an interrupted call.
pub const STICKY_TIMEOUTS: u32 = 0x400_0000;
/// Address space limited to 3 GiB.
pub const ADDR_LIMIT_3GB: u32 = 0x800_0000;

/// Execution-domain byte (`PER_LINUX`, `PER_LINUX32`, `PER_SVR4`, …).
pub const PER_MASK: u32 = 0x00ff;
/// Default Linux execution domain.
pub const PER_LINUX: u32 = 0x0000;

/// Security-relevant bits Linux clears on a setuid/setgid exec.
pub const PER_CLEAR_ON_SETID: u32 =
    READ_IMPLIES_EXEC | ADDR_NO_RANDOMIZE | ADDR_COMPAT_LAYOUT | MMAP_PAGE_ZERO;

/// `personality(0xffffffff)` reads the persona without setting it — the only
/// argument value that is a pure query. Linux `SYSCALL_DEFINE1(personality)`:
/// `if (personality != 0xffffffff) set_personality(personality);`
pub const PERSONALITY_QUERY: u32 = 0xffff_ffff;

/// Linux `SYSCALL_DEFINE1(personality)`: always returns the PREVIOUS persona;
/// sets the new one unless `persona` is the query sentinel.
/// # C: O(1)
pub fn get_set(cur: &Task, persona: u32) -> u32 {
    let prev = cur.personality.load(Ordering::Acquire);
    if persona != PERSONALITY_QUERY { cur.personality.store(persona, Ordering::Release); }
    prev
}

/// Current persona. # C: O(1)
pub fn get(cur: &Task) -> u32 { cur.personality.load(Ordering::Acquire) }

/// Whether `PROT_READ` must imply `PROT_EXEC` for this task's mappings.
/// # C: O(1)
pub fn read_implies_exec(cur: &Task) -> bool {
    get(cur) & READ_IMPLIES_EXEC != 0
}

/// Whether `uname(2)` must report a faked 2.6.x release for this task.
/// # C: O(1)
pub fn uname26(cur: &Task) -> bool { get(cur) & UNAME26 != 0 }

/// Linux `override_release` (`kernel/sys.c`): rewrite `X.Y.Z<rest>` as
/// `2.6.<Y+60><rest>` for `UNAME26` processes, so programs that reject a
/// "Linux 3.0"-or-newer release string keep working.
///
/// The version prefix is scanned exactly as Linux does: consume digits and
/// dots, stopping at the third dot or at the first character that is neither.
/// Everything from there on (`-oxide`, `-rc1`, …) is appended verbatim.
/// Returns the byte count written to `out`.
/// # C: O(len)
pub fn override_release(release: &[u8], out: &mut [u8]) -> usize {
    let mut ndots = 0usize;
    let mut rest = 0usize;
    while rest < release.len() {
        let b = release[rest];
        if b == b'.' {
            ndots += 1;
            if ndots >= 3 { break; }
        } else if !b.is_ascii_digit() {
            break;
        }
        rest += 1;
    }
    let patchlevel = release_patchlevel(release);
    let mut n = 0usize;
    let mut put = |byte: u8, out: &mut [u8], n: &mut usize| {
        if *n < out.len() { out[*n] = byte; *n += 1; }
    };
    for b in b"2.6." { put(*b, out, &mut n); }
    let faked = patchlevel + UNAME26_PATCHLEVEL_BIAS;
    let mut digits = [0u8; 10];
    let mut d = 0usize;
    let mut v = faked;
    loop {
        digits[d] = b'0' + (v % 10) as u8;
        d += 1;
        v /= 10;
        if v == 0 { break; }
    }
    while d > 0 { d -= 1; put(digits[d], out, &mut n); }
    for b in &release[rest..] { put(*b, out, &mut n); }
    n
}

/// Linux `LINUX_VERSION_PATCHLEVEL + 60` — the constant that maps a modern
/// `X.Y` onto the 2.6 series.
const UNAME26_PATCHLEVEL_BIAS: u32 = 60;

/// Minor ("patchlevel") number of an `X.Y.Z…` release string; 0 when absent.
/// # C: O(len)
fn release_patchlevel(release: &[u8]) -> u32 {
    let mut it = release.split(|b| *b == b'.');
    let _major = it.next();
    let Some(minor) = it.next() else { return 0 };
    let mut v: u32 = 0;
    for b in minor {
        if !b.is_ascii_digit() { break; }
        v = v.saturating_mul(10).saturating_add((b - b'0') as u32);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_release_maps_5_15_to_2_6_75() {
        let mut out = [0u8; 65];
        let n = override_release(b"5.15.0-oxide", &mut out);
        assert_eq!(&out[..n], b"2.6.75-oxide");
    }

    #[test]
    fn override_release_keeps_third_dot_tail() {
        let mut out = [0u8; 65];
        let n = override_release(b"6.1.2.3", &mut out);
        assert_eq!(&out[..n], b"2.6.61.3");
    }

    #[test]
    fn override_release_without_suffix() {
        let mut out = [0u8; 65];
        let n = override_release(b"4.0.0", &mut out);
        assert_eq!(&out[..n], b"2.6.60");
    }

    #[test]
    fn per_clear_on_setid_matches_uapi() {
        assert_eq!(PER_CLEAR_ON_SETID, 0x0400000 | 0x0040000 | 0x0200000 | 0x0100000);
    }
}
