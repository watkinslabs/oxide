//! Reparent the existing presentation drawable after canonical tree mutation.
use super::{Backend,BackendError,Rect};
use crate::ffi;

impl Backend {
    pub(super) fn reparent(&mut self,hwnd:u32,parent:u32,rect:Rect)->Result<(),BackendError>{
        let window=self.windows.get(&hwnd).ok_or(BackendError::InvalidCommand)?;
        let xid=window.xid;
        let parent=if parent==0{self.root}else{self.windows.get(&parent).ok_or(BackendError::InvalidCommand)?.xid};
        if xid==parent{return Err(BackendError::InvalidCommand);}
        let x=i16::try_from(rect.left).map_err(|_|BackendError::InvalidCommand)?;
        let y=i16::try_from(rect.top).map_err(|_|BackendError::InvalidCommand)?;
        let sequence=unsafe{let cookie=ffi::xcb_reparent_window_checked(self.conn,xid,parent,x,y);
            let sequence=cookie.sequence;super::requests::finish(self.conn,hwnd,vec![cookie])?;sequence};
        let window=self.windows.get_mut(&hwnd).ok_or(BackendError::InvalidCommand)?;
        window.parent=parent;window.rect=rect;window.configure_sequence=Some(sequence);
        // A server reparent loses visible pixels. Existing retained coverage
        // repaints through Show when visible, and remains retained when hidden.
        if window.requested_visible{self.show(hwnd)?;}
        Ok(())
    }
}
