//! Robust hibernation prepare/post notifier chain.

use sync::{Spinlock, TaskList as PowerListClass};

use crate::decide::{Error, KResult};

const MAX_NOTIFIERS: usize = 32;

/// Notification delivered outside the registry lock.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Event { Prepare, Post }

/// One blocking power-event callback.
pub type Notifier = fn(Event) -> KResult<()>;

static NOTIFIERS: Spinlock<[Option<Notifier>; MAX_NOTIFIERS], PowerListClass> =
    Spinlock::new([None; MAX_NOTIFIERS]);

/// Register one boot-lifetime notifier in deterministic call order.
/// # C: O(MAX_NOTIFIERS)
pub fn register(notifier: Notifier) -> KResult<()> {
    let mut slots = NOTIFIERS.lock();
    let slot = slots.iter_mut().find(|slot| slot.is_none()).ok_or(Error::Nomem)?;
    *slot = Some(notifier);
    Ok(())
}

/// Notify every registered owner before system mutation is frozen.
/// A refusal posts the already-prepared prefix in reverse order.
/// # C: O(MAX_NOTIFIERS)
/// # Sleeps: callback-defined
pub fn prepare() -> KResult<()> {
    let callbacks = *NOTIFIERS.lock();
    let mut completed = 0usize;
    for callback in callbacks.iter().flatten() {
        if let Err(error) = callback(Event::Prepare) {
            for undo in callbacks[..completed].iter().rev().flatten() {
                let _ = undo(Event::Post);
            }
            return Err(error);
        }
        completed += 1;
    }
    Ok(())
}

/// Post every registered owner in reverse prepare order. # C: O(MAX_NOTIFIERS)
/// # Sleeps: callback-defined
pub fn post() {
    let callbacks = *NOTIFIERS.lock();
    for callback in callbacks.iter().rev().flatten() { let _ = callback(Event::Post); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    static TRACE: AtomicU32 = AtomicU32::new(0);

    fn first(event: Event) -> KResult<()> {
        TRACE.fetch_or(match event { Event::Prepare => 1, Event::Post => 4 }, Ordering::AcqRel);
        Ok(())
    }
    fn refuses(event: Event) -> KResult<()> {
        if event == Event::Prepare { Err(Error::Busy) } else { Ok(()) }
    }

    #[test]
    fn refusal_posts_the_successful_prefix() {
        *NOTIFIERS.lock() = [None; MAX_NOTIFIERS];
        TRACE.store(0, Ordering::Release);
        register(first).unwrap();
        register(refuses).unwrap();
        assert_eq!(prepare(), Err(Error::Busy));
        assert_eq!(TRACE.load(Ordering::Acquire), 5);
        *NOTIFIERS.lock() = [None; MAX_NOTIFIERS];
    }
}
