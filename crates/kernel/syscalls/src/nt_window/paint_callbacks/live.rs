use super::*;
use super::super::{GUI, send, STATUS_PENDING};
use alloc::sync::Arc;

/// Called after canonical region/HDC preparation, outside GUI/GDI locks.
/// # C: O(processes + callbacks); # Sleeps: yes
pub(crate) fn for_current(resources: Resources, completion: Completion) -> u64 {
    let token = (|| {
        let cur = sched::live::current().filter(|cur| cur.is_nt_personality())?;
        let mut entries = GUI.lock();
        let entry = entries.iter_mut().find(|e| e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
        let hwnd = u32::try_from(resources.hwnd).ok().and_then(ipc::win32_window::WindowId::from_raw)?;
        let owner=entry.state.get(hwnd)?.owner_tid;
        match completion{
            Completion::Erase(p) if p.tid==cur.tid as u64=>{},
            Completion::Erase(_)=>return None,
            _ if owner!=cur.tid as u64=>return None,
            _=>{},
        }
        entry.paint_callbacks.admit(cur.tid as u64, resources, completion)
    })();
    match token { Some(token) => resume(token, Ok(0)), None => finish(completion, Err(())) }
}

/// Resume retained state; owner completion handles exact-HDC validation and cleanup.
/// # C: O(processes + callbacks); # Sleeps: yes
pub(crate) fn resume(token: u64, mut result: Result<u64, ()>) -> u64 {
    let Some(cur) = sched::live::current().filter(|cur| cur.is_nt_personality()) else { return 0; };
    loop {
        let step = {
            let mut entries = GUI.lock();
            let Some(entry) = entries.iter_mut().find(|e| e.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else { return 0; };
            match result {
                Ok(value) => entry.paint_callbacks.step(cur.tid as u64, token, value).map(Ok),
                Err(()) => entry.paint_callbacks.fail(cur.tid as u64, token).map(Err),
            }
        };
        match step {
            None => return 0,
            Some(Err(completion)) => return finish(completion, Err(())),
            Some(Ok(Step::Failed(completion))) => return finish(completion, Err(())),
            Some(Ok(Step::Finish(completion, erase))) => return finish(completion, Ok(erase)),
            Some(Ok(Step::Send { hwnd, message, wparam })) => {
                result = match send::send_resumable_current(hwnd, message, wparam, 0, send::Continuation { token, resume }) {
                    send::SendOutcome::Pending => return STATUS_PENDING,
                    send::SendOutcome::Complete(value) => Ok(value),
                    send::SendOutcome::Failed => Err(()),
                };
            }
        }
    }
}
fn finish(completion:Completion,result:Result<bool,()>)->u64{match completion{
    Completion::Callback{token,finish}=>finish(token,result),
    Completion::Paint(p)=>super::super::paint_prepare::finish_for_current(p,result),
    Completion::Erase(p)=>super::super::redraw::erase::finish_for_current(p,result),
}}
/// After queue removal, release payload resources in the same process without invoking user continuations.
/// # C: O(processes + windows + GDI objects)
pub(crate) fn dispose_for_current(completion:Completion){
    match completion{
        Completion::Paint(p)=>super::super::paint_prepare::discard_for_current(p),
        Completion::Erase(p)=>super::super::redraw::erase::discard_for_current(p),
        Completion::Callback{..}=>{},
    }
}
/// Foreign destruction never frees preparation resources still used by an active WndProc.
/// # C: O(processes * preparations); no GUI lock across resource cleanup
pub(crate) fn cancel_window_current(hwnd:u64){
    let Some(cur)=sched::live::current()else{return;};
    loop{
        let completion={let mut entries=GUI.lock();let Some(e)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))else{return;};
            e.paint_callbacks.cancel_window(hwnd);e.paint_callbacks.take_window(hwnd)};
        match completion{Some(c)=>dispose_for_current(c),None=>return}
    }
}
/// Drain before canonical window/GDI/MM teardown; never resume user code on the retiring sender.
/// # C: O(processes * preparations); no GUI lock across resource cleanup
pub(crate) fn cancel_current_thread(){
    let Some(cur)=sched::live::current()else{return;};
    loop{
        let completion={let mut entries=GUI.lock();entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))
            .and_then(|e|e.paint_callbacks.retire_thread(cur.tid as u64,|tid,hwnd|e.sent.has_foreign_active(tid,hwnd)))};
        match completion{
            Some(completion)=>dispose_for_current(completion),
            None=>return,
        }
    }
}
/// Send completion/recipient exit invokes after dropping GUI; never resume a retired sender.
/// # C: O(processes * preparations * sends)
pub(crate) fn reap_retired_current(){
    let Some(cur)=sched::live::current()else{return;};
    loop{
        let completion={let mut entries=GUI.lock();entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))
            .and_then(|e|e.paint_callbacks.take_retired(|tid,hwnd|e.sent.has_foreign_active(tid,hwnd)))};
        match completion{Some(c)=>dispose_for_current(c),None=>return}
    }
}
