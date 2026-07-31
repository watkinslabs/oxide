// UAPI-shaped constants for the usermode helper (`<linux/umh.h>`).

/// Queue the helper and return immediately. The caller gets no useful error if
/// the program could not be exec'd; the request is safe to make from a context
/// that must not sleep.
pub const UMH_NO_WAIT: i32 = 0x00;
/// Wait until the exec has been attempted; the return value is the exec result
/// (0, or a negated errno such as `-ENOENT` when the binary is absent).
pub const UMH_WAIT_EXEC: i32 = 0x01;
/// Wait until the helper process terminates; the return value is the
/// `wait(2)`-encoded status, not an errno (`request_key`'s upcall reads it with
/// the `W*` macros).
pub const UMH_WAIT_PROC: i32 = 0x02;
/// A fatal signal aborts the wait.
pub const UMH_KILLABLE: i32 = 0x04;
/// The wait counts as freezable for suspend.
pub const UMH_FREEZABLE: i32 = 0x08;

/// Bits a caller may legally pass alongside a wait mode.
pub const UMH_WAIT_MODE_MASK: i32 = UMH_WAIT_EXEC | UMH_WAIT_PROC;
/// Every defined bit.
pub const UMH_FLAG_MASK: i32 = UMH_WAIT_MODE_MASK | UMH_KILLABLE | UMH_FREEZABLE;

/// Gate state. `Disabled` is the boot-time value: no helper may run until the
/// system has finished bringing userspace up, and suspend/hibernate re-enters
/// it so a helper cannot be spawned against a frozen userspace.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UmhDisableDepth {
    Enabled  = 0,
    Freezing = 1,
    Disabled = 2,
}

impl UmhDisableDepth {
    /// # C: O(1)
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Enabled,
            1 => Self::Freezing,
            _ => Self::Disabled,
        }
    }
    /// True while any depth other than `Enabled` is installed. # C: O(1)
    pub const fn is_disabled(self) -> bool { !matches!(self, Self::Enabled) }
}

/// Seconds `usermodehelper_disable` waits for in-flight helpers to drain before
/// giving up and re-enabling (Linux `RUNNING_HELPERS_TIMEOUT`, 5 s).
pub const RUNNING_HELPERS_TIMEOUT_MS: u64 = 5_000;

/// Kernel-thread umask the helper starts from. A helper inherits the initial
/// kernel `fs_struct`, whose umask is 0; the exec path resets it to the login
/// default so a helper-created file is not world-writable.
pub const UMH_UMASK: u32 = 0o022;
