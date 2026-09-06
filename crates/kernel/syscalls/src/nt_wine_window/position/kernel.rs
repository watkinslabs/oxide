use super::{Context, Request, policy::{self, Owner}};
struct Current { request:Option<Request> }
impl Owner for Current {
    fn context(&mut self, hwnd: u64) -> Option<Context> { crate::nt_window::position_context_for_current(hwnd) }
    fn commit(&mut self, request: Request) -> bool { self.request=Some(request);true }
}
/// Snapshot/plan only; successful non-sibling insertion is a no-op. # C: O(windows)
pub(crate) fn plan_current(args:&[u64;7])->Result<Option<Request>,()> {
    let mut owner=Current {request:None};
    if policy::set(&mut owner,args)==0 {Err(())}else{Ok(owner.request)}
}
/// Raw NtUserSetWindowPos ordinal 0x15a7, argc=7, BOOL result. # C: O(canonical windows + publication)
pub(crate) fn set(args: &[u64;7]) -> u64 {
    if let Some(result)=crate::nt_window::position::queue_position_for_current(args){return result;}
    match plan_current(args) {Err(())=>0,Ok(None)=>1,Ok(Some(request))=>crate::nt_window::position_apply_for_current(request)}
}
