extern crate alloc;
extern crate self as sched;
extern crate self as uaccess;
pub use canonical_sched::{Task, registry, nt_native_thread, nt_object};
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;
static SERIAL: Mutex<()> = Mutex::new(());
thread_local! {
    static OUTPUT: std::cell::RefCell<Vec<(u64,u64)>> = const {std::cell::RefCell::new(Vec::new())};
    static FAIL_WRITE: std::cell::Cell<bool> = const {std::cell::Cell::new(false)};
    static INITIALIZED: std::cell::Cell<bool> = const {std::cell::Cell::new(false)};
}
pub fn put_user_u64(address:u64,value:u64)->Result<(),()> {
    if FAIL_WRITE.get() {return Err(());}
    assert!(address==0x1000 || address==0x1008);
    OUTPUT.with(|out|out.borrow_mut().push((address,value))); Ok(())
}
// Only current-runqueue installation is hosted. Task, registry, process default,
// native creation state, VMM and the complete TEB builder are production owners.
pub fn initialize_current_process(task:&Task) {
    assert!(task.is_nt_personality());
    let expected=task.thread_group.nt_default_desktop.lock().object().unwrap();
    assert!(Arc::ptr_eq(&task.nt_desktop.lock().object().expect("inheritance before runtime initialization"),&expected));
    INITIALIZED.set(true);
}
mod lifecycle {include!(concat!(env!("OUT_DIR"),"/prepare.rs"));}

#[cfg(test)]
mod tests;
