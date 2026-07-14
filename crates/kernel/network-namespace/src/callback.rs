use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

/// Atomic-wakeup-only notifier invoked synchronously by the final owner drop.
/// Implementations must be reentrant, allocation-free, lock-free, and IRQ-safe.
/// # Ctx: any, including IRQ-off and while unrelated locks are held
/// # Sleeps: no
pub type FinalDropCallback = fn();

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InstallError { AlreadyInstalled }

pub(crate) struct CallbackSlot { callback: AtomicPtr<()> }

/// Apply the callback slot's install-once transition. # C: O(1)
pub(crate) fn install_transition<T: Copy + Eq>(null: T, value: T,
    compare_exchange: impl FnOnce(T, T, Ordering, Ordering) -> Result<T, T>)
    -> Result<(), InstallError>
{
    match compare_exchange(null, value, Ordering::Release, Ordering::Acquire) {
        Ok(_) => Ok(()),
        Err(current) if current == value => Ok(()),
        Err(_) => Err(InstallError::AlreadyInstalled),
    }
}

/// Decode a non-null published callback value. # C: O(1)
pub(crate) fn published<T: Copy + Eq>(null: T, value: T) -> Option<T> {
    if value == null { None } else { Some(value) }
}

impl CallbackSlot {
    /// Create an empty callback slot. # C: O(1)
    pub(crate) const fn new() -> Self { Self { callback: AtomicPtr::new(ptr::null_mut()) } }

    /// Install one immutable callback value. # C: O(1)
    pub(crate) fn install(&self, callback: FinalDropCallback) -> Result<(), InstallError> {
        let value = callback as *mut ();
        install_transition(ptr::null_mut(), value,
            |null, value, success, failure| self.callback.compare_exchange(
                null, value, success, failure))
    }

    /// Test whether callback publication completed. # C: O(1)
    pub(crate) fn installed(&self) -> bool {
        published(ptr::null_mut(), self.callback.load(Ordering::Acquire)).is_some()
    }

    /// Invoke the published callback when installed. # C: O(1)
    pub(crate) fn notify(&self) {
        let value = self.callback.load(Ordering::Acquire);
        let Some(value) = published(ptr::null_mut(), value) else { return; };
        // SAFETY: install accepts only a `fn()` and stores its unchanged code
        // pointer; the slot is never cleared or replaced after publication.
        let callback: FinalDropCallback = unsafe { core::mem::transmute(value) };
        callback();
    }
}

static FINAL_DROP: CallbackSlot = CallbackSlot::new();

/// Install the final-drop notifier; identical reinstall is idempotent.
/// # C: O(1)
/// # Ctx: process initialization; installed callback must satisfy `FinalDropCallback`
/// # Sleeps: no
pub fn install_final_drop_callback(callback: FinalDropCallback) -> Result<(), InstallError> {
    FINAL_DROP.install(callback)
}

/// Test whether global callback publication completed. # C: O(1)
pub(crate) fn installed() -> bool { FINAL_DROP.installed() }
/// Invoke the global callback when installed. # C: O(1)
pub(crate) fn notify() { FINAL_DROP.notify(); }
