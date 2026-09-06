use super::layout::*;
use super::super::{GUI,bridge,STATUS_PENDING};
use alloc::sync::Arc;
use crate::nt_wine_window::position::{Context,Request,Order,plan_current};
use ipc::win32_window::{WindowId,WindowRect,WindowPosition,PositionOrder};
use super::continuation::{self,Continuation,Outcome};
#[path="nccalc.rs"]mod nccalc;
const WM_WINDOWPOSCHANGING:u64=0x0046;
const WM_WINDOWPOSCHANGED:u64=0x0047;
const WM_NCCALCSIZE:u64=0x0083;
const NOACTIVATE:u32=0x0010;
const FRAMECHANGED:u32=0x0020;
const HIDE:u32=0x0080;
const NOCLIENTSIZE:u32=0x0800;
const NOCLIENTMOVE:u32=0x1000;
const WS_CHILD:u32=0x4000_0000;
const WS_EX_TOPMOST:u32=0x0008;
const MAX_PENDING:usize=64;

#[derive(Clone)]
pub(crate) struct PendingPosition {
    pub(super) token:u64,pub(super) tid:u64,pub(super) request:Request,pub(super) remote:bool,pub(super) cancelled:bool,wndproc:u64,pointer:u64,
    old:WindowRect,old_client:WindowRect,client:Option<WindowRect>,class_style:u32,valid:Option<[WindowRect;2]>,
    pub(super) reply:Option<Arc<super::work::Reply>>,resume_send:Option<Arc<super::work::Reply>>,
    caller:Option<Continuation>,
}
/// Canonical process and HWND validation before a transient snapshot. # C: O(processes + windows)
pub(crate) fn position_context_for_current(hwnd:u64)->Option<Context> {
    let cur=sched::live::current()?;if !cur.is_nt_personality(){return None;}
    let id=WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    let entries=GUI.lock();let entry=entries.iter().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    let record=entry.state.get(id)?;
    Some(Context {rect:entry.state.rect(id)?,parent:record.parent.map(|id|id.raw() as u64),style:record.style,visible:record.visible})
}
fn take(token:u64)->Option<PendingPosition> {
    let cur=sched::live::current()?;let mut entries=GUI.lock();
    let entry=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    let index=entry.pending_positions.iter().position(|p|p.token==token&&p.tid==cur.tid as u64)?;
    Some(entry.pending_positions.swap_remove(index))
}
fn callback(p:PendingPosition,kind:u64,message:u64,wparam:u64,payload:&[u8])->u64 {
    let Some(cur)=sched::live::current() else{return 0;};
    {
        let mut entries=GUI.lock();let Some(entry)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else{return 0;};
        if entry.pending_positions.len()>=MAX_PENDING||entry.pending_positions.try_reserve(1).is_err(){return 0;}
        entry.pending_positions.push(p.clone());
    }
    let completion=sched::nt_callback::Completion {kind,argument:p.token};
    let relocations:&[(usize,usize)]=if kind==NCCALC {&[(NCCALC_POINTER as usize,NCCALC_WINPOS as usize)]}else{&[]};
    match crate::nt_rtl::begin_wndproc_payload_callback(p.request.hwnd,message,wparam,p.wndproc,payload,relocations,completion) {
        Err(_)=>{let _=take(p.token);0}
        Ok(pointer)=>{
            let mut entries=GUI.lock();
            if let Some(entry)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) {
                // Destruction on another thread may have cancelled this entry
                // during payload installation. Never replace that cancellation.
                if let Some(stored)=entry.pending_positions.iter_mut().find(|v|v.token==p.token){stored.pointer=pointer;return STATUS_PENDING;}
            }0
        }
    }
}
/// Begin synchronous position callbacks; final result is BOOL, pending is internal control flow.
/// # C: O(processes + windows); # Sleeps: yes (publication only after GUI unlock)
pub(crate) fn position_apply_for_current(request:Request)->u64 {
    start(request,false,None,None)
}
/// Immediate outcomes return directly; a suspended chain resumes its original owner-thread caller.
/// # C: O(processes + windows); # Sleeps: yes
pub(crate) fn position_apply_resumable_for_current(request:Request,caller:Option<Continuation>)->Outcome{
    continuation::outcome(start_inner(request,false,None,None,caller))
}
pub(super) fn start(request:Request,remote:bool,reply:Option<Arc<super::work::Reply>>,resume_send:Option<Arc<super::work::Reply>>)->u64 {
    start_inner(request,remote,reply,resume_send,None)
}
fn start_inner(request:Request,remote:bool,reply:Option<Arc<super::work::Reply>>,resume_send:Option<Arc<super::work::Reply>>,caller:Option<Continuation>)->u64 {
    let Some(cur)=sched::live::current() else{return 0;};if !cur.is_nt_personality(){return 0;}
    let Some(id)=u32::try_from(request.hwnd).ok().and_then(WindowId::from_raw) else{return 0;};
    let p={
        let mut entries=GUI.lock();let Some(entry)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else{return 0;};
        let Some(record)=entry.state.get(id) else{return 0;};
        if record.owner_tid!=cur.tid as u64{return 0;}
        let Some(old)=entry.state.rect(id) else{return 0;};
        let token=entry.next_create;let Some(next)=token.checked_add(1) else{return 0;};entry.next_create=next;
        PendingPosition {token,tid:cur.tid as u64,request,remote,cancelled:false,wndproc:record.wndproc,pointer:0,old,old_client:record.client_rect.unwrap_or(old),client:None,class_style:0,valid:None,reply,resume_send,caller}
    };
    if p.wndproc!=0&&request.flags&NOSENDCHANGING==0 {callback(p,CHANGING,WM_WINDOWPOSCHANGING,0,&encode(request))}
    else {after_changing(p)}
}
fn after_changing(mut p:PendingPosition)->u64 {
    if p.request.flags&NOSIZE==0||p.request.flags&FRAMECHANGED!=0 {
        let Some(cur)=sched::live::current()else{return 0;};
        let class_style={let entries=GUI.lock();entries.iter().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))
            .and_then(|e|WindowId::from_raw(p.request.hwnd as u32).and_then(|id|e.state.position_class_style(id)))};
        let Some(class_style)=class_style else{return 0;};p.class_style=class_style;
        if p.wndproc!=0 {
            let mut bytes=[0;NCCALC_BYTES];bytes[..16].copy_from_slice(&encode_rect(p.request.rect));
            bytes[16..32].copy_from_slice(&encode_rect(p.old));bytes[32..48].copy_from_slice(&encode_rect(p.old_client));
            bytes[NCCALC_WINPOS as usize..].copy_from_slice(&encode(p.request));
            return callback(p,NCCALC,WM_NCCALCSIZE,1,&bytes);
        }
        p.client=Some(p.request.rect);
    }else{
        let dx=p.request.rect.left as i64-p.old.left as i64;let dy=p.request.rect.top as i64-p.old.top as i64;
        let shift=|value:i32,delta:i64|i32::try_from(value as i64+delta).ok();
        let (Some(left),Some(top),Some(right),Some(bottom))=(shift(p.old_client.left,dx),shift(p.old_client.top,dy),shift(p.old_client.right,dx),shift(p.old_client.bottom,dy)) else{return 0;};
        p.client=Some(WindowRect {left,top,right,bottom});
    }
    p.valid=nccalc::valid(p.old_client,p.client.unwrap_or(p.request.rect),p.class_style,0,p.request.flags,[p.old_client;2]);
    commit(p)
}
fn commit(mut p:PendingPosition)->u64 {
    let Some(cur)=sched::live::current() else{return 0;};
    let Some(id)=u32::try_from(p.request.hwnd).ok().and_then(WindowId::from_raw) else{return 0;};
    let order=match p.request.order {
        None=>None,Some(Order::Top)=>Some(PositionOrder::Top),Some(Order::Bottom)=>Some(PositionOrder::Bottom),
        Some(Order::Topmost)=>Some(PositionOrder::Topmost),Some(Order::NotTopmost)=>Some(PositionOrder::NotTopmost),
        Some(Order::After(raw))=>{let Some(id)=u32::try_from(raw).ok().and_then(WindowId::from_raw) else{return 0;};Some(PositionOrder::After(id))}
    };
    let client=p.client.unwrap_or(p.request.rect);
    p.request.flags|=NOCLIENTMOVE|NOCLIENTSIZE;
    if (client.left,client.top)!=(p.old_client.left,p.old_client.top){p.request.flags&=!NOCLIENTMOVE;}
    if (client.right as i64-client.left as i64,client.bottom as i64-client.top as i64)
        !=(p.old_client.right as i64-p.old_client.left as i64,p.old_client.bottom as i64-p.old_client.top as i64){p.request.flags&=!NOCLIENTSIZE;}
    let (wait,activate,stack)={
        let mut entries=GUI.lock();let Some(entry)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else{return 0;};
        let Some(record)=entry.state.get(id) else{return 0;};
        let activate=p.request.flags&(NOACTIVATE|HIDE)==0&&record.style&WS_CHILD==0;
        let change=WindowPosition {window:id,rect:p.request.rect,client:p.client,order,visible:p.request.visible,flags:p.request.flags,notify_geometry:p.wndproc==0};
        if entry.state.apply_position_preserving(cur.tid as u64,change,p.valid).is_err(){return 0;}
        let mut stack=alloc::vec::Vec::new();
        if p.request.order.is_some(){
            let mut previous=None;
            for sibling in entry.state.position_siblings(record.parent).into_iter().rev(){
                let Some(r)=entry.state.get(sibling)else{continue;};
                if !r.presentation_ready{continue;}
                let insertion=previous.unwrap_or(if r.ex_style&WS_EX_TOPMOST!=0 {u64::MAX}else{0});
                stack.push((sibling.raw() as u64,insertion));previous=Some(sibling.raw() as u64);
            }
        }
        entry.foreground=entry.state.active_window().is_some();(Arc::clone(&entry.wait),activate,stack)
    };
    wait.wake_all();
    if crate::nt_gdi::position_preserve_for_current(id.raw(),p.old,p.request.rect,p.valid,p.request.flags).is_err(){return 0;}
    if bridge::publish_geometry_current(p.request.hwnd).is_err(){return 0;}
    if p.request.visible.is_some()&&bridge::publish_visibility_current(p.request.hwnd).is_err(){return 0;}
    for (hwnd,insertion) in stack {if bridge::publish_position_current(hwnd,Some(insertion),false).is_err(){return 0;}}
    if activate&&bridge::publish_position_current(p.request.hwnd,None,true).is_err(){return 0;}
    if p.wndproc!=0 {let bytes=encode(p.request);callback(p,CHANGED,WM_WINDOWPOSCHANGED,0,&bytes)}else{1}
}
/// Resume only a matching current-thread canonical transaction. # C: O(processes + windows + publication)
pub(crate) fn complete_position_callback(completion:sched::nt_callback::Completion,callback_result:u64)->u64 {
    let Some(mut p)=take(completion.argument) else{return 0;};
    let remote=p.remote;
    let reply=p.reply.clone();let resume_send=p.resume_send.clone();
    let caller=p.caller;
    let result=if p.cancelled{0}else{(||{match completion.kind {
        CHANGING=>{
            let mut bytes=[0;WINDOWPOS_BYTES];if uaccess::copy_from_user(&mut bytes,p.pointer).is_err(){return 0;}
            let Some(args)=decode(&bytes,p.request.hwnd) else{return 0;};
            match plan_current(&args) {Err(())=>0,Ok(None)=>1,Ok(Some(request))=>{p.request=request;after_changing(p)}}
        }
        NCCALC=>{
            let mut bytes=[0;48];if uaccess::copy_from_user(&mut bytes,p.pointer).is_err(){return 0;}
            let Some(client)=decode_rect(bytes[..16].try_into().unwrap()) else{return 0;};
            let raw_rect=|offset:usize|{let n=|i:usize|i32::from_le_bytes(bytes[offset+i*4..offset+i*4+4].try_into().unwrap());WindowRect{left:n(0),top:n(1),right:n(2),bottom:n(3)}};
            p.valid=nccalc::valid(p.old_client,client,p.class_style,callback_result as u32,p.request.flags,[raw_rect(16),raw_rect(32)]);
            p.client=Some(client);commit(p)
        }
        CHANGED=>1,
        _=>0,
    }})()};
    if result==STATUS_PENDING{return result;}
    super::remote::finish_reply(reply.as_ref(),result);
    if let Some(result)=continuation::finish(caller,result){return result;}
    if let Some(reply)=resume_send {super::remote::wait_reply(reply)}
    else if remote {super::super::resume_position_message_current()}else{result}
}
