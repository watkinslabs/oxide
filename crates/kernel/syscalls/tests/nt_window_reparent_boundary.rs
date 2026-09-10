//! Actual SetParent hook: canonical mutation precedes unlocked publication.
extern crate alloc;
use ipc::win32_window::{WindowId,WindowManager};
use std::cell::RefCell;
thread_local!{static STATE:RefCell<WindowManager>=RefCell::new(WindowManager::new());static SENT:RefCell<Vec<(u64,Option<WindowId>)>>=RefCell::new(Vec::new());}
fn valid_window(hwnd:u64)->Option<WindowId>{WindowId::from_raw(u32::try_from(hwnd).ok()?)}
mod access{
    use super::*;
    pub(crate) fn with_state<T>(f:impl FnOnce(&WindowManager)->T)->Option<T>{Some(STATE.with(|s|f(&s.borrow())))}
    pub(crate) fn with_state_mut<T>(f:impl FnOnce(&mut WindowManager)->T)->Option<T>{Some(STATE.with(|s|f(&mut s.borrow_mut())))}
}
mod bridge{
    use super::*;
    pub(crate) fn publish_reparent_current(hwnd:u64)->Result<(),()>{
        STATE.with(|s|{let state=s.try_borrow_mut().expect("GUI owner released before publication");
            let parent=state.get(valid_window(hwnd).unwrap()).unwrap().parent;
            SENT.with(|sent|sent.borrow_mut().push((hwnd,parent)));});Ok(())
    }
}
mod nt_gdi{pub(crate) fn lease_window_for_current(_:u32)->Option<u32>{None}}
#[path="nt_window_reparent_boundary/fixture.rs"]mod fixture;
#[test]
fn actual_set_parent_publishes_changed_canonical_parent_only(){
    let (parent,child)=access::with_state_mut(|s|{let parent=s.create(0,None,0).unwrap();let child=s.create(0,Some(parent),0).unwrap();(parent,child)}).unwrap();
    assert_eq!(fixture::set_parent_for_current(child.raw() as u64,0),Ok(parent.raw() as u64));
    assert_eq!(SENT.with(|s|s.borrow().clone()),vec![(child.raw() as u64,None)]);
    assert_eq!(fixture::set_parent_for_current(child.raw() as u64,0),Ok(0));
    assert!(fixture::set_parent_for_current(child.raw() as u64,child.raw() as u64).is_err());
    assert_eq!(SENT.with(|s|s.borrow().len()),1);
    assert_eq!(fixture::set_parent_for_current(child.raw() as u64,parent.raw() as u64),Ok(0));
    assert_eq!(SENT.with(|s|s.borrow().last().copied()),Some((child.raw() as u64,Some(parent))));
}
