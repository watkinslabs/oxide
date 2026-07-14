use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

pub type FinalDropCallback = fn();

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InstallError { AlreadyInstalled }

pub(crate) struct CallbackSlot { callback: AtomicPtr<()> }

impl CallbackSlot {
    pub(crate) const fn new() -> Self { Self { callback: AtomicPtr::new(ptr::null_mut()) } }

    pub(crate) fn install(&self, callback: FinalDropCallback) -> Result<(), InstallError> {
        let value = callback as *mut ();
        match self.callback.compare_exchange(ptr::null_mut(), value,
            Ordering::Release, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(current) if current == value => Ok(()),
            Err(_) => Err(InstallError::AlreadyInstalled),
        }
    }

    pub(crate) fn installed(&self) -> bool {
        !self.callback.load(Ordering::Acquire).is_null()
    }

    pub(crate) fn notify(&self) {
        let value = self.callback.load(Ordering::Acquire);
        if value.is_null() { return; }
        // SAFETY: install accepts only a `fn()` and stores its unchanged code
        // pointer; the slot is never cleared or replaced after publication.
        let callback: FinalDropCallback = unsafe { core::mem::transmute(value) };
        callback();
    }
}

static FINAL_DROP: CallbackSlot = CallbackSlot::new();

/// Install the nonblocking final-drop notifier; identical reinstall is idempotent. # C: O(1)
pub fn install_final_drop_callback(callback: FinalDropCallback) -> Result<(), InstallError> {
    FINAL_DROP.install(callback)
}

pub(crate) fn installed() -> bool { FINAL_DROP.installed() }
pub(crate) fn notify() { FINAL_DROP.notify(); }
