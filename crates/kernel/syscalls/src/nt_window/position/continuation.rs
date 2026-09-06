//! Caller completion is distinct from intermediate WndProc return values.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum Outcome {Complete(bool),Failed,Pending}
#[derive(Clone,Copy)]
pub(crate) struct Continuation {pub token:u64,pub resume:fn(u64,Outcome)->u64}
/// Decode only the native position adapter's BOOL/control result, never a WndProc LRESULT. # C: O(1)
pub(super) fn outcome(result:u64)->Outcome{match result{1=>Outcome::Complete(true),0x103=>Outcome::Pending,_=>Outcome::Failed}}
/// Pending chains retain caller state; only final completion invokes its continuation. # C: O(1)
pub(super) fn finish(caller:Option<Continuation>,result:u64)->Option<u64>{
    let state=outcome(result);if state==Outcome::Pending{return None;}
    caller.map(|c|(c.resume)(c.token,state))
}
#[cfg(test)]
#[path="../tests/position_continuation.rs"]mod tests;
