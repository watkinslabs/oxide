// `syslog(2)` / `klogctl(3)` decision logic — Linux `kernel/printk/printk.c`
// (`syslog_action_restricted`, `check_syslog_permissions`, the argument
// validation at the head of each `do_syslog` case).
//
// Hosted-testable: pure functions over scalars, no `sched`/`hal`/user memory.
// The kernel-side shim (`103_syslog.rs`) supplies the capability bit and the
// `dmesg_restrict` sysctl value and performs the copies.

use syscall::errno::Errno;

/// `SYSLOG_ACTION_*` (`include/uapi/linux/kernel.h` via `linux/syslog.h`).
pub const ACTION_CLOSE:         u32 = 0;
pub const ACTION_OPEN:          u32 = 1;
pub const ACTION_READ:          u32 = 2;
pub const ACTION_READ_ALL:      u32 = 3;
pub const ACTION_READ_CLEAR:    u32 = 4;
pub const ACTION_CLEAR:         u32 = 5;
pub const ACTION_CONSOLE_OFF:   u32 = 6;
pub const ACTION_CONSOLE_ON:    u32 = 7;
pub const ACTION_CONSOLE_LEVEL: u32 = 8;
pub const ACTION_SIZE_UNREAD:   u32 = 9;
pub const ACTION_SIZE_BUFFER:   u32 = 10;

/// Linux `syslog_action_restricted`. With `dmesg_restrict` set every action
/// needs CAP_SYSLOG; otherwise READ_ALL and SIZE_BUFFER are open to all.
/// # C: O(1)
pub fn action_restricted(action: u32, dmesg_restrict: bool) -> bool {
    if dmesg_restrict { return true; }
    action != ACTION_READ_ALL && action != ACTION_SIZE_BUFFER
}

/// Linux `check_syslog_permissions` for `SYSLOG_FROM_READER` (the `syslog(2)`
/// source; `/proc/kmsg` checks at open instead). CAP_SYSLOG only — the
/// CAP_SYS_ADMIN fallback was removed from Linux, so granting it here would
/// be a privilege widening, not compatibility.
/// # C: O(1)
pub fn check_permissions(action: u32, cap_syslog: bool, dmesg_restrict: bool)
    -> Result<(), Errno>
{
    if action_restricted(action, dmesg_restrict) && !cap_syslog {
        return Err(Errno::Eperm);
    }
    Ok(())
}

/// Outcome of validating a READ / READ_ALL / READ_CLEAR argument pair,
/// before any user memory is touched.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ReadArgs {
    /// `len == 0`: Linux returns 0 without inspecting `buf`.
    Empty,
    /// Copy at most this many bytes.
    Len(usize),
}

/// Linux `do_syslog` READ-family head: `if (!buf || len < 0) return -EINVAL;`
/// then `if (!len) return 0;` then `access_ok`. Note the ordering — a NULL
/// buffer is EINVAL, not EFAULT, and a negative length is EINVAL even when
/// `buf` is valid. The `access_ok` (EFAULT) step is the shim's job.
/// # C: O(1)
pub fn validate_read(buf: u64, len: i32) -> Result<ReadArgs, Errno> {
    if buf == 0 || len < 0 { return Err(Errno::Einval); }
    if len == 0 { return Ok(ReadArgs::Empty); }
    Ok(ReadArgs::Len(len as usize))
}

/// Linux `SYSLOG_ACTION_CONSOLE_LEVEL`: `len < 1 || len > 8` is EINVAL;
/// otherwise the value is clamped up to `minimum_console_loglevel`.
/// # C: O(1)
pub fn validate_console_level(len: i32) -> Result<u32, Errno> {
    if len < 1 || len > klog::syslog::CONSOLE_LOGLEVEL_DEBUG as i32 {
        return Err(Errno::Einval);
    }
    let lvl = len as u32;
    Ok(if lvl < klog::syslog::MINIMUM_CONSOLE_LOGLEVEL {
        klog::syslog::MINIMUM_CONSOLE_LOGLEVEL
    } else { lvl })
}

/// Unknown action number — Linux `do_syslog` default arm.
/// # C: O(1)
pub fn is_known_action(action: u32) -> bool { action <= ACTION_SIZE_BUFFER }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_allows_read_all_and_size_buffer_without_cap() {
        for a in [ACTION_READ_ALL, ACTION_SIZE_BUFFER] {
            assert!(check_permissions(a, false, false).is_ok(), "action {a}");
        }
    }

    #[test]
    fn unrestricted_denies_every_other_action_without_cap() {
        for a in [ACTION_CLOSE, ACTION_OPEN, ACTION_READ, ACTION_READ_CLEAR,
                  ACTION_CLEAR, ACTION_CONSOLE_OFF, ACTION_CONSOLE_ON,
                  ACTION_CONSOLE_LEVEL, ACTION_SIZE_UNREAD] {
            assert_eq!(check_permissions(a, false, false), Err(Errno::Eperm), "action {a}");
        }
    }

    #[test]
    fn dmesg_restrict_closes_read_all_and_size_buffer() {
        for a in [ACTION_READ_ALL, ACTION_SIZE_BUFFER] {
            assert_eq!(check_permissions(a, false, true), Err(Errno::Eperm), "action {a}");
            assert!(check_permissions(a, true, true).is_ok(), "action {a} with cap");
        }
    }

    #[test]
    fn cap_syslog_allows_everything() {
        for a in 0..=ACTION_SIZE_BUFFER {
            assert!(check_permissions(a, true, false).is_ok());
            assert!(check_permissions(a, true, true).is_ok());
        }
    }

    #[test]
    fn null_buf_is_einval_not_efault() {
        assert_eq!(validate_read(0, 16), Err(Errno::Einval));
        // Even with len == 0 the NULL check fires first (Linux order).
        assert_eq!(validate_read(0, 0), Err(Errno::Einval));
    }

    #[test]
    fn negative_len_is_einval() {
        assert_eq!(validate_read(0x1000, -1), Err(Errno::Einval));
        assert_eq!(validate_read(0x1000, i32::MIN), Err(Errno::Einval));
    }

    #[test]
    fn zero_len_short_circuits_before_access_ok() {
        assert_eq!(validate_read(0x1000, 0), Ok(ReadArgs::Empty));
    }

    #[test]
    fn positive_len_passes_through() {
        assert_eq!(validate_read(0x1000, 4096), Ok(ReadArgs::Len(4096)));
    }

    #[test]
    fn console_level_accepts_one_through_eight() {
        for l in 1..=8i32 {
            assert_eq!(validate_console_level(l), Ok(l as u32));
        }
    }

    #[test]
    fn console_level_rejects_outside_range() {
        for l in [i32::MIN, -1, 0, 9, 100, i32::MAX] {
            assert_eq!(validate_console_level(l), Err(Errno::Einval), "level {l}");
        }
    }

    #[test]
    fn unknown_action_rejected() {
        assert!(is_known_action(ACTION_SIZE_BUFFER));
        assert!(!is_known_action(11));
        assert!(!is_known_action(u32::MAX));
    }
}
