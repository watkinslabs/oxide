use alloc::vec::Vec;
const MAX_PREPARATIONS: usize = 64;
const WM_NCPAINT: u32 = 0x0085;
const WM_ERASEBKGND: u32 = 0x0014;

/// Owner completion writes fErase/returns HDC or releases ERASENOW resources.
/// It must also release resources on Err; no callback executes after sender teardown.
#[derive(Clone, Copy)]
pub(crate) enum Completion {
    Callback { token:u64, finish:fn(u64,Result<bool,()>)->u64 },
    Paint(super::super::paint_prepare::Prepared),
    Erase(super::super::redraw::erase::ErasePrepared),
}
#[derive(Clone, Copy)]
pub(crate) struct Resources {
    pub hwnd: u64, pub dc: u64, pub nc_region: u64,
    pub erase: bool, pub delayed: bool, pub empty_clip: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { Nonclient, Erase, Done }
#[derive(Clone, Copy)]
struct Pending { token: u64, tid: u64, resources: Resources, phase: Phase, needed: bool, completion: Completion, in_flight:bool, cancelled:bool, retired:bool }
pub(crate) struct Queue { next: u64, pending: Vec<Pending> }
pub(crate) enum Step { Send { hwnd: u64, message: u32, wparam: u64 }, Finish(Completion, bool), Failed(Completion) }
impl Queue {
    pub(crate) fn new() -> Self { Self { next: 1, pending: Vec::new() } }
    pub(crate) fn admit(&mut self, tid: u64, resources: Resources, completion: Completion) -> Option<u64> {
        if self.pending.len() == MAX_PREPARATIONS || resources.hwnd == 0
            || resources.erase && !resources.empty_clip && resources.dc == 0 { return None; }
        let next = self.next.checked_add(1)?;
        self.pending.try_reserve(1).ok()?;
        let token = self.next; self.next = next;
        self.pending.push(Pending { token, tid, resources, phase: Phase::Nonclient, needed: resources.delayed, completion, in_flight:false, cancelled:false, retired:false });
        Some(token)
    }
    pub(crate) fn step(&mut self, tid: u64, token: u64, result: u64) -> Option<Step> {
        let index = self.pending.iter().position(|p| p.tid == tid && p.token == token)?;
        if self.pending[index].cancelled{return Some(Step::Failed(self.pending.remove(index).completion));}
        let p = &mut self.pending[index];
        p.in_flight=false;
        if p.phase == Phase::Done { p.needed = result == 0; }
        if p.phase == Phase::Nonclient {
            p.phase = Phase::Erase;
            if p.resources.nc_region != 0 { p.in_flight=true;return Some(Step::Send { hwnd: p.resources.hwnd, message: WM_NCPAINT, wparam: p.resources.nc_region }); }
        }
        if p.phase == Phase::Erase {
            p.phase = Phase::Done;
            if p.resources.erase && !p.resources.empty_clip { p.in_flight=true;return Some(Step::Send { hwnd: p.resources.hwnd, message: WM_ERASEBKGND, wparam: p.resources.dc }); }
        }
        let p = self.pending.remove(index); Some(Step::Finish(p.completion, p.needed))
    }
    pub(crate) fn fail(&mut self, tid: u64, token: u64) -> Option<Completion> {
        let index = self.pending.iter().position(|p| p.tid == tid && p.token == token)?;
        Some(self.pending.remove(index).completion)
    }
    /// Drain one payload at a time; cleanup occurs after releasing GUI, without allocation.
    #[cfg(test)]
    pub(crate) fn take_thread(&mut self,tid:u64)->Option<Completion>{
        let index=self.pending.iter().position(|p|p.tid==tid)?;
        Some(self.pending.remove(index).completion)
    }
    /// Mark retiring sender state but keep payloads used by a surviving foreign Send callback.
    pub(crate) fn retire_thread(&mut self,tid:u64,mut active:impl FnMut(u64,u64)->bool)->Option<Completion>{
        for p in &mut self.pending{if p.tid==tid{p.retired=true;p.cancelled=true;}}
        self.take_retired(&mut active)
    }
    pub(crate) fn take_retired(&mut self,mut active:impl FnMut(u64,u64)->bool)->Option<Completion>{
        let index=self.pending.iter().position(|p|p.retired&&!active(p.tid,p.resources.hwnd))?;
        Some(self.pending.remove(index).completion)
    }
    /// Mark cancellation before draining; active Send keeps its resource payload until return.
    pub(crate) fn cancel_window(&mut self,hwnd:u64){for p in &mut self.pending{if p.resources.hwnd==hwnd{p.cancelled=true;}}}
    /// Destruction keeps a leased fresh paint HDC alive until its active callback returns.
    pub(crate) fn holds_dc(&self,dc:u32)->bool{self.pending.iter().any(|p|p.in_flight&&match p.completion{
        Completion::Paint(prepared)=>prepared.dc==dc,Completion::Erase(prepared)=>prepared.dc==dc,Completion::Callback{..}=>false,
    })}
    /// Only quiescent entries may release HDC/HRGN before a callback return.
    pub(crate) fn take_window(&mut self,hwnd:u64)->Option<Completion>{
        let index=self.pending.iter().position(|p|p.resources.hwnd==hwnd&&!p.in_flight)?;
        Some(self.pending.remove(index).completion)
    }
}


#[cfg(test)]
#[path="tests.rs"] mod tests;
