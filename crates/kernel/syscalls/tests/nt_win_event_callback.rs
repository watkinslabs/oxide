//! Production WinEvent callback admission; client execution is instrumented.
extern crate alloc;
#[path = "../src/nt_window/families/hook_event.rs"]
mod hook_event;
#[path = "../src/nt_window/tests/hook_event.rs"]
mod cases;
mod nt_user_callback { pub enum Input<'a> { Record(&'a [u8]) } }
mod nt_rtl {
    use std::cell::RefCell;
    use sched::nt_callback::Completion;
    thread_local! { pub static CALL: RefCell<Option<(u32, Vec<u8>, Completion)>> = const { RefCell::new(None) }; }
    pub fn begin_user_callback(index: u32, input: super::nt_user_callback::Input<'_>, completion: Completion) -> u64 {
        let super::nt_user_callback::Input::Record(bytes) = input;
        CALL.with(|call| *call.borrow_mut() = Some((index, bytes.to_vec(), completion)));
        0x103
    }
}
