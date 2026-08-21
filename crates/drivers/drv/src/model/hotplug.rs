//! Sleepable exclusion between model mutation and power transitions.

use sched::live::{Mutex, MutexGuard};
use sync::{Spinlock, TaskList as HotplugStateLock};

static HOTPLUG: Mutex<()> = Mutex::new(());
static STATE: Spinlock<State, HotplugStateLock> = Spinlock::new(State::free());

const MODE_FREE: u8 = 0;
const MODE_MUTATION: u8 = 1;
const MODE_FREEZE: u8 = 2;
#[cfg(not(test))]
const BOOT_OWNER: u64 = u64::MAX;

/// Device-model mutation exclusion retained across a power transaction.
pub struct HotplugGuard(#[allow(dead_code)] Option<MutexGuard<'static, ()>>);

pub(super) struct OperationGuard(#[allow(dead_code)] Option<MutexGuard<'static, ()>>);

#[derive(Copy, Clone)]
struct State { owner: u64, mode: u8 }

impl State {
    const fn free() -> Self { Self { owner: 0, mode: MODE_FREE } }
}

fn owner() -> u64 {
    #[cfg(test)]
    {
        std::thread_local! { static TOKEN: u8 = const { 0 }; }
        return TOKEN.with(|token| token as *const u8 as u64);
    }
    #[cfg(not(test))]
    { sched::live::current().map(|task| u64::from(task.tid) + 1).unwrap_or(BOOT_OWNER) }
}

fn acquire() -> crate::KResult<MutexGuard<'static, ()>> {
    if let Some(guard) = HOTPLUG.try_lock() { return Ok(guard); }
    if !sched::live::runqueue_active() { return Err(crate::Error::Busy); }
    // SAFETY: live model mutation runs in process context before taking model spinlocks.
    Ok(unsafe { HOTPLUG.lock() })
}

fn publish(mode: u8, owner: u64) {
    *STATE.lock() = State { owner, mode };
}

fn release() {
    *STATE.lock() = State::free();
}

/// Exclude device publication/removal until this guard drops.
/// # C: O(contention)
/// # Sleeps: yes
pub fn freeze_hotplug() -> HotplugGuard {
    // SAFETY: hibernation calls from process context with no spinlock held.
    let guard = unsafe { HOTPLUG.lock() };
    publish(MODE_FREEZE, owner());
    HotplugGuard(Some(guard))
}

pub(super) fn operation() -> crate::KResult<OperationGuard> {
    let current = owner();
    let state = *STATE.lock();
    if state.owner == current {
        return match state.mode {
            MODE_MUTATION => Ok(OperationGuard(None)),
            MODE_FREEZE => Err(crate::Error::Busy),
            _ => Err(crate::Error::Busy),
        };
    }
    let guard = acquire()?;
    publish(MODE_MUTATION, current);
    Ok(OperationGuard(Some(guard)))
}

impl Drop for HotplugGuard {
    fn drop(&mut self) {
        release();
        let _ = self.0.take();
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        if self.0.is_some() {
            release();
            let _ = self.0.take();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::sync::Arc;

    #[test]
    fn power_guard_stabilizes_the_canonical_device_registry() {
        let _model = crate::model::test_claim::claim_model();
        let guard = freeze_hotplug();
        let blocked = Arc::new(crate::Device::new("test-hotplug", String::from("frozen"), 0, 0, 0));
        assert!(matches!(crate::try_device_add(blocked), Err(crate::Error::Busy)));
        drop(guard);
        let live = Arc::new(crate::Device::new("test-hotplug", String::from("thawed"), 0, 0, 0));
        let live = crate::try_device_add(live).unwrap();
        crate::device_del(&live);
    }
}
