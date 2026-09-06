//! Canonical position transaction; window vector order is bottom-to-top.
use super::*;
#[path="position/damage.rs"]mod damage;
const NOREDRAW:u32=0x0008;
const NOACTIVATE:u32=0x0010;
const FRAMECHANGED:u32=0x0020;
const HIDEWINDOW:u32=0x0080;
const NOCOPYBITS:u32=0x0100;
const WS_CHILD:u32=0x4000_0000;
const WS_POPUP:u32=0x8000_0000;
const WS_MINIMIZE:u32=0x2000_0000;
const WS_EX_TOPMOST:u32=0x0008;
const WM_CHILDACTIVATE:u32=0x0022;

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum PositionOrder { Top,Bottom,Topmost,NotTopmost,After(WindowId) }
#[derive(Clone,Copy,Debug)]
pub struct WindowPosition {
    pub window:WindowId,pub rect:WindowRect,pub client:Option<WindowRect>,
    pub order:Option<PositionOrder>,pub visible:Option<bool>,pub flags:u32,
    pub notify_geometry:bool,
}

impl WindowManager {
    /// Read class flags from the canonical class identity; unclassified HWNDs have zero flags. # C: O(windows + classes)
    pub fn position_class_style(&self,id:WindowId)->Option<u32>{
        let record=self.get(id)?;Some(record.class_atom.and_then(|atom|self.classes.iter().find(|c|c.atom==atom)).map_or(0,|c|c.style))
    }
    /// Popup ownership is distinct from child parentage; reject cycles before mutation. # C: O(windows²)
    pub fn set_popup_owner(&mut self,id:WindowId,owner:Option<WindowId>)->Result<(),WindowError> {
        let record=self.get(id).ok_or(WindowError::NoSuchWindow)?;
        if record.style&(WS_CHILD|WS_POPUP)==WS_CHILD{return Err(WindowError::InvalidParent);}
        let mut cursor=owner;
        for _ in 0..=self.windows.len(){
            let Some(next)=cursor else{break;};if next==id{return Err(WindowError::InvalidParent);}
            let r=self.get(next).ok_or(WindowError::NoSuchWindow)?;
            if r.style&(WS_CHILD|WS_POPUP)==WS_CHILD{return Err(WindowError::InvalidParent);}
            cursor=r.owner;
        }
        if cursor.is_some(){return Err(WindowError::InvalidParent);}
        self.windows.iter_mut().find(|(window,_)|*window==id).ok_or(WindowError::NoSuchWindow)?.1.owner=owner;
        Ok(())
    }
    /// Enumerate canonical siblings bottom-to-top; no secondary order registry. # C: O(windows)
    pub fn position_siblings(&self,parent:Option<WindowId>)->Vec<WindowId> {
        self.windows.iter().filter_map(|(id,r)|(r.parent==parent).then_some(*id)).collect()
    }
    /// Apply admitted state and notification changes under the canonical owner's exclusive lock.
    /// Callback-capable callers deliver WINDOWPOSCHANGED themselves after publication.
    /// # C: O(windows² + queues); # Sleeps: no
    pub fn apply_position(&mut self,tid:u64,p:WindowPosition)->Result<(),WindowError> {
        self.apply_position_preserving(tid,p,None)
    }
    /// Apply caller-computed NCCALCSIZE destination/source preservation without losing pending damage.
    /// # C: O(windows² + queues + region operations); # Sleeps: no
    pub fn apply_position_preserving(&mut self,tid:u64,p:WindowPosition,valid:Option<[WindowRect;2]>)->Result<(),WindowError> {
        let id=p.window;
        let record=self.get(id).ok_or(WindowError::NoSuchWindow)?;
        if record.owner_tid!=tid {return Err(WindowError::WrongThread);}
        let old=self.rect(id).ok_or(WindowError::NoSuchWindow)?;
        let width=p.rect.right.checked_sub(p.rect.left).filter(|v|*v>=0).ok_or(WindowError::InvalidParent)?;
        let height=p.rect.bottom.checked_sub(p.rect.top).filter(|v|*v>=0).ok_or(WindowError::InvalidParent)?;
        if let Some(client)=p.client {
            if client.right.checked_sub(client.left).filter(|n|*n>=0).is_none()
                ||client.bottom.checked_sub(client.top).filter(|n|*n>=0).is_none() {return Err(WindowError::InvalidParent);}
        }
        if let Some(PositionOrder::After(after))=p.order {
            let sibling=self.get(after).ok_or(WindowError::NoSuchWindow)?;
            if sibling.parent!=record.parent {return Err(WindowError::InvalidParent);}
        }
        let moved=(old.left,old.top)!=(p.rect.left,p.rect.top);
        let resized=(old.right as i64-old.left as i64,old.bottom as i64-old.top as i64)!=(width as i64,height as i64);
        let visible=p.visible.unwrap_or(record.visible);
        let child=record.style&(WS_CHILD|WS_POPUP)==WS_CHILD;
        let activate=p.flags&(NOACTIVATE|HIDEWINDOW)==0&&record.style&WS_MINIMIZE==0;
        let client=p.client.or(record.client_rect).unwrap_or(p.rect);
        let repaint=p.flags&NOREDRAW==0&&visible&&width>0&&height>0&&client.right>client.left&&client.bottom>client.top
            &&(resized||client!=record.client_rect.unwrap_or(old)||p.flags&FRAMECHANGED!=0||!record.visible||p.flags&NOCOPYBITS!=0);
        let damage=if repaint{Some(self.position_damage(id,p,valid)?)}else{None};
        if repaint&&!self.dirty.iter().any(|(window,_)|*window==id){self.dirty.try_reserve(1).map_err(|_|WindowError::NoMemory)?;}
        let paint_message=damage.as_ref().is_some_and(|d|d.pending())&&!self.dirty.iter().any(|(window,_)|*window==id);
        let messages=usize::from(p.notify_geometry&&moved)+usize::from(p.notify_geometry&&resized)
            +usize::from(activate&&child)+usize::from(paint_message);
        self.check_message_capacity(id,messages)?;
        // Activation can notify both old/new thread queues and their top-level windows.
        // Admission covers that complete bounded batch before any position mutation.
        if activate&&!child||!visible&&self.active==Some(id) {
            let bound=self.windows.len().checked_mul(2).and_then(|n|n.checked_add(8)).ok_or(WindowError::QueueFull)?;
            for (owner,_) in &self.queues {
                let needed=bound+if *owner==tid {messages}else{0};
                if !self.queue_has_capacity(*owner,needed) {return Err(WindowError::QueueFull);}
            }
        }
        if let Some(order)=p.order {self.position_reorder(id,record.parent,order)?;}
        self.set_rect(id,p.rect)?;
        let target=&mut self.windows.iter_mut().find(|(window,_)|*window==id).ok_or(WindowError::NoSuchWindow)?.1;
        target.visible=visible;
        if visible {target.style|=WS_VISIBLE;}else{target.style&=!WS_VISIBLE;}
        if let Some(client)=p.client {target.client_rect=Some(client);}
        if p.notify_geometry&&moved {self.post_to_window(id,WinMessage {hwnd:Some(id),message:WM_MOVE,wparam:0,lparam:mouse_lparam(p.rect.left,p.rect.top)})?;}
        if p.notify_geometry&&resized {self.post_to_window(id,WinMessage {hwnd:Some(id),message:WM_SIZE,wparam:0,lparam:mouse_lparam(width,height)})?;}
        if let Some(damage)=damage{
            if let Some(index)=self.dirty.iter().position(|(window,_)|*window==id){
                if damage.pending(){self.dirty[index].1=damage;}else{self.dirty.remove(index);}
            }else if damage.pending(){self.dirty.push((id,damage));}
        }
        if activate {
            if child {self.post_to_window(id,WinMessage {hwnd:Some(id),message:WM_CHILDACTIVATE,wparam:0,lparam:0})?;}
            else {self.compositor_focus(id,true)?;}
        }else if !visible&&self.active==Some(id) {self.compositor_focus(id,false)?;}
        Ok(())
    }
    fn position_reorder(&mut self,id:WindowId,parent:Option<WindowId>,order:PositionOrder)->Result<(),WindowError> {
        if order==PositionOrder::After(id) {return Ok(());}
        if order==PositionOrder::NotTopmost&&self.get(id).is_some_and(|r|r.ex_style&WS_EX_TOPMOST==0){return Ok(());}
        let index=self.windows.iter().position(|(window,_)|*window==id).ok_or(WindowError::NoSuchWindow)?;
        let mut item=self.windows.remove(index);
        match order {
            PositionOrder::Topmost=>item.1.ex_style|=WS_EX_TOPMOST,
            PositionOrder::Bottom|PositionOrder::NotTopmost=>item.1.ex_style&=!WS_EX_TOPMOST,
            PositionOrder::After(after)=>{
                if self.get(after).is_some_and(|r|r.ex_style&WS_EX_TOPMOST==0) {item.1.ex_style&=!WS_EX_TOPMOST;}
                else {
                    let below=self.windows.iter().position(|(window,_)|*window==after)
                        .and_then(|index|self.windows[..index].iter().rev().find(|(_,r)|r.parent==parent));
                    if below.is_some_and(|(_,r)|r.ex_style&WS_EX_TOPMOST!=0){item.1.ex_style|=WS_EX_TOPMOST;}
                }
            }
            PositionOrder::Top=>{}
        }
        let slot=match order {
            PositionOrder::After(after)=>self.windows.iter().position(|(window,_)|*window==after).unwrap_or(index.min(self.windows.len())),
            PositionOrder::Bottom=>self.windows.iter().position(|(_,r)|r.parent==parent).unwrap_or(self.windows.len()),
            _=>{
                let topmost=item.1.ex_style&WS_EX_TOPMOST!=0;
                if !topmost {self.windows.iter().position(|(_,r)|r.parent==parent&&r.ex_style&WS_EX_TOPMOST!=0)
                    .unwrap_or_else(||self.windows.iter().rposition(|(_,r)|r.parent==parent).map_or(self.windows.len(),|n|n+1))}
                else {self.windows.iter().rposition(|(_,r)|r.parent==parent).map_or(self.windows.len(),|n|n+1)}
            }
        };
        self.windows.insert(slot,item);
        self.position_owned_order();Ok(())
    }
    fn position_owned_order(&mut self) {
        // Visit upper popups first so lifting a group retains its internal sibling order.
        let ids:Vec<_>=self.windows.iter().rev().map(|(id,_)|*id).collect();
        for _ in 0..self.windows.len(){
            let mut changed=false;
            for id in &ids {
                let Some(record)=self.get(*id)else{continue;};let Some(owner)=record.owner else{continue;};
                let Some(oi)=self.windows.iter().position(|(id,_)|*id==owner)else{continue;};
                let Some(wi)=self.windows.iter().position(|(candidate,_)|candidate==id)else{continue;};
                if wi<=oi {
                    let mut item=self.windows.remove(wi);let index=self.windows.iter().position(|(id,_)|*id==owner).unwrap();
                    if self.windows[index].1.ex_style&WS_EX_TOPMOST!=0{item.1.ex_style|=WS_EX_TOPMOST;}
                    self.windows.insert(index+1,item);changed=true;
                }
            }
            if !changed{break;}
        }
    }
}

#[cfg(test)]
#[path="tests/position.rs"]
mod tests;
