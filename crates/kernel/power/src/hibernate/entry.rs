//! One public write-side hibernation entry.

use sync::{Spinlock, TaskList as PowerListClass};

use crate::decide::{Error, KResult};

type HibernateHook = fn() -> KResult<()>;
type ResumeHook = fn();

/// Complete machine adapters for image write and immediate resume probing.
#[derive(Copy, Clone)]
pub struct MachineHooks { hibernate: HibernateHook, resume: ResumeHook }

impl MachineHooks {
    /// Join both entry points to one complete machine implementation. # C: O(1)
    pub const fn new(hibernate: HibernateHook, resume: ResumeHook) -> Self {
        Self { hibernate, resume }
    }
}

static MACHINE: Spinlock<Option<MachineHooks>, PowerListClass> = Spinlock::new(None);

/// Install the machine adapter after its cold restore path is complete.
/// # C: O(1)
pub fn set_machine_hooks(hooks: Option<MachineHooks>) { *MACHINE.lock() = hooks; }

/// Whether policy and a complete machine adapter admit hibernation. # C: O(1)
pub fn available() -> bool {
    MACHINE.lock().is_some() && super::settings::get()
        .map(|settings| settings.hibernate_enabled()).unwrap_or(false)
}

/// Run the one installed write-side transaction. # C: backend-defined
/// # Ctx: process context
/// # Sleeps: yes
pub fn hibernate() -> KResult<()> {
    if !super::settings::get().map(|settings| settings.hibernate_enabled()).unwrap_or(false) {
        return Err(Error::Perm);
    }
    let hooks = (*MACHINE.lock()).ok_or(Error::Opnotsupp)?;
    (hooks.hibernate)()
}

/// Probe the configured resume target through the installed machine owner.
/// # C: backend-defined
/// # Ctx: process context
/// # Sleeps: yes
pub fn software_resume() -> KResult<()> {
    let hooks = (*MACHINE.lock()).ok_or(Error::Opnotsupp)?;
    (hooks.resume)();
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use super::*;

    static CALLS: AtomicUsize = AtomicUsize::new(0);

    fn machine() -> KResult<()> { CALLS.fetch_add(1, Ordering::AcqRel); Ok(()) }
    fn resume() { CALLS.fetch_add(1, Ordering::AcqRel); }

    #[test]
    fn availability_and_dispatch_share_one_hook() {
        let _g = crate::suspend::test_lock();
        super::super::settings::init(0);
        set_machine_hooks(None);
        assert!(!available());
        assert_eq!(hibernate(), Err(Error::Opnotsupp));
        set_machine_hooks(Some(MachineHooks::new(machine, resume)));
        let before = CALLS.load(Ordering::Acquire);
        assert!(available());
        assert_eq!(hibernate(), Ok(()));
        assert_eq!(CALLS.load(Ordering::Acquire), before + 1);
        assert_eq!(software_resume(), Ok(()));
        assert_eq!(CALLS.load(Ordering::Acquire), before + 2);
        set_machine_hooks(None);
    }
}
