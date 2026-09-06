//! Production Erase lifetime with only the outer redraw scan completion instrumented.
#[path="../redraw/erase.rs"]mod contract;
#[path="hosted_erase.rs"]pub(crate) mod erase;
pub(crate) fn resume(token:u64,result:Result<u64,()>)->u64{
    super::ENV.with(|e|e.borrow_mut().erase_finished.push((token,result)));token
}
