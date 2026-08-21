// Per-controller process and hard-IRQ ownership. The process side may sleep
// or poll hardware; the IRQ side is a separate, bounded register-state lock.

extern crate alloc;

use alloc::sync::Arc;
use sched::live::Mutex;
use sync::{Spinlock, TaskList as HdaRegClass};

pub type RegLock<R> = Spinlock<R, HdaRegClass>;

pub struct ControllerLocks<P, R> {
    pub process: Mutex<P>,
    pub reg: Arc<RegLock<R>>,
}

impl<P, R> ControllerLocks<P, R> {
    /// # C: O(1)
    #[cfg(test)]
    pub fn new(process: P, reg: R) -> Self {
        Self { process: Mutex::new(process), reg: Arc::new(Spinlock::new(reg)) }
    }

    /// # C: O(1)
    pub fn from_reg(process: P, reg: Arc<RegLock<R>>) -> Self {
        Self { process: Mutex::new(process), reg }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_polling_never_owns_the_irq_register_gate() {
        let locks = ControllerLocks::new(1u32, 2u32);
        let process = locks.process.try_lock().expect("process state");
        let mut irq = locks.reg.lock();
        *irq += 1;
        assert_eq!((*process, *irq), (1, 3));
    }
}
