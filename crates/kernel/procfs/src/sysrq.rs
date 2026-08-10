// `/proc/sysrq-trigger` — the magic-SysRq commands, reachable without a
// keyboard.
//
// This is the only way to ask a machine to do the things sysrq does when the
// console is a pipe: a serial line carries a break, but a script, a service
// unit and an ssh session do not. It is also the only way to make a kernel
// panic on purpose, which is what a staged crash kernel exists to catch — with
// no trigger there is no way to exercise that path on a running machine at all.
//
// Write-only by mode, and every decision it makes lives in the sysrq command
// table, so what a key means here cannot drift from what it means on the
// serial line.

use alloc::sync::Arc;

use vfs::{mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

/// Write-only, owner-only: the file's mode IS its permission check, exactly as
/// the reference leaves it. A readable trigger would be a file whose contents
/// are "nothing" and whose only purpose is to be written.
pub const MODE: u16 = 0o200;

/// Bytes a write consumes.
///
/// The whole write is reported consumed regardless of length: a caller
/// shell-echoing `c` sends `c\n`, and reporting one byte written of two makes
/// the shell retry with the newline — which would run a SECOND command, the
/// unbound one. Only the first byte is a command.
/// # C: O(1)
pub fn consumed(len: usize) -> usize { len }

/// The byte a write means, or `None` for an empty write.
///
/// An empty write is not an error and not a command: `> /proc/sysrq-trigger`
/// truncating the file must not crash the machine.
/// # C: O(1)
pub fn command_byte(src: &[u8]) -> Option<u8> { src.first().copied() }

struct SysrqTriggerOps;

impl FileOps for SysrqTriggerOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }

    /// Refused, not empty. The file has no contents and the mode already says
    /// so; answering a read with EOF would make a `cat` look like it worked.
    /// # C: O(1)
    fn read(&self, _inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Err(VfsError::Einval) }

    /// # C: see the sysrq command
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        if let Some(key) = command_byte(buf) { run(key); }
        Ok(consumed(buf.len()))
    }
}

#[cfg(target_os = "oxide-kernel")]
fn run(key: u8) { sched::diag::sysrq_trigger(key); }

#[cfg(not(target_os = "oxide-kernel"))]
fn run(_key: u8) {}

/// `i_op` for the trigger. Overrides only `truncate`, which must succeed as a
/// no-op: the default answers EROFS, and a shell redirection opens with
/// `O_TRUNC`, so `echo c > /proc/sysrq-trigger` — the way every operator and
/// every script uses this file — reported "Read-only file system" and did
/// nothing at all. Observed on a boot with a crash image staged.
struct SysrqTriggerInodeOps;
impl InodeOps for SysrqTriggerInodeOps {
    /// # C: O(1)
    fn truncate(&self, _inode: &Inode, _len: u64) -> KResult<()> { Ok(()) }
}

/// `/proc/sysrq-trigger` inode. # C: O(1)
pub fn make_proc_sysrq_trigger() -> InodeRef {
    InodeBuilder::new(crate::ids::SYSRQ_TRIGGER as vfs::Ino,
                      mk_mode(FileType::Regular, MODE),
                      Arc::new(SysrqTriggerInodeOps), Arc::new(SysrqTriggerOps)).build()
}

/// Default `kernel.sysrq`. `1` is "every command", which is what the sysrq
/// table treats it as; a machine that wants less writes a bit mask.
pub const SYSRQ_DEFAULT: i64 = 1;

/// Range the leaf accepts: every combination of the defined bits.
pub const SYSRQ_BOUNDS: (i64, i64) = (0, 511);

/// `kernel.sysrq` — the live enable mask the serial key path consults.
///
/// A stored-only leaf is worse than no leaf: it reports a setting an
/// administrator believes is in force while every key press ignores it.
/// # C: O(1)
pub fn mask() -> i64 { live_mask() as i64 }

/// # C: O(1)
pub fn set_mask(v: i64) { set_live_mask(v.clamp(SYSRQ_BOUNDS.0, SYSRQ_BOUNDS.1) as u32); }

#[cfg(target_os = "oxide-kernel")]
fn live_mask() -> u32 { sched::diag::sysrq::mask_value() }
#[cfg(target_os = "oxide-kernel")]
fn set_live_mask(v: u32) { sched::diag::set_sysrq_mask(v); }

#[cfg(not(target_os = "oxide-kernel"))]
fn live_mask() -> u32 { HOSTED_MASK.load(core::sync::atomic::Ordering::Relaxed) }
#[cfg(not(target_os = "oxide-kernel"))]
fn set_live_mask(v: u32) { HOSTED_MASK.store(v, core::sync::atomic::Ordering::Relaxed); }
#[cfg(not(target_os = "oxide-kernel"))]
static HOSTED_MASK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

#[cfg(test)]
mod tests {
    use super::*;

    /// Write-only. A mode that let anyone read it would publish a file whose
    /// only meaning is what happens when it is written.
    #[test]
    fn the_trigger_is_write_only_and_owner_only() {
        assert_eq!(MODE, 0o200);
    }

    /// A shell redirection opens with `O_TRUNC`, and the default answer to a
    /// truncate on a procfs leaf is EROFS. That made the one spelling everyone
    /// uses — `echo c > /proc/sysrq-trigger` — fail before the write ever ran.
    #[test]
    fn truncating_the_trigger_succeeds_so_a_shell_redirection_reaches_the_write() {
        let ino = make_proc_sysrq_trigger();
        assert!(SysrqTriggerInodeOps.truncate(&ino, 0).is_ok());
    }

    /// A shell writes `c\n`. Consuming one byte makes the shell re-issue the
    /// rest, which runs the newline as a second command.
    #[test]
    fn a_whole_write_is_consumed_so_a_shell_does_not_retry_the_newline() {
        assert_eq!(consumed(2), 2);
        assert_eq!(command_byte(b"c\n"), Some(b'c'));
    }

    /// Truncating the file must not be a command.
    #[test]
    fn an_empty_write_is_not_a_command() {
        assert_eq!(command_byte(b""), None);
        assert_eq!(consumed(0), 0);
    }

    /// Only the FIRST byte. A write of several letters is one command, not a
    /// sequence — the reference reads a single character and stops.
    #[test]
    fn only_the_first_byte_of_a_longer_write_is_the_command() {
        assert_eq!(command_byte(b"tc"), Some(b't'));
    }

    /// The leaf must READ BACK what was written, or an administrator is
    /// looking at a number that is not the one in force. This leaf was a
    /// stored constant with no reader at all.
    #[test]
    fn the_enable_mask_leaf_reads_back_what_was_written() {
        let saved = mask();
        set_mask(0);
        assert_eq!(mask(), 0);
        set_mask(4);
        assert_eq!(mask(), 4);
        set_mask(saved);
    }

    /// Out-of-range values are clamped to the declared window rather than
    /// stored, so nothing downstream sees a mask the leaf says is impossible.
    #[test]
    fn a_value_outside_the_window_is_clamped_to_it() {
        let saved = mask();
        set_mask(-5);
        assert_eq!(mask(), SYSRQ_BOUNDS.0);
        set_mask(9999);
        assert_eq!(mask(), SYSRQ_BOUNDS.1);
        set_mask(saved);
    }
}
