//! Map acceptance and retained-frame replay share the backend's ordered X connection.
use super::{Backend,BackendError,Rect,ffi};
impl Backend {
    pub(super) fn show(&mut self,hwnd:u32)->Result<(),BackendError>{
        let window=self.windows.get_mut(&hwnd).ok_or(BackendError::InvalidCommand)?;
        window.requested_visible=true;
        if window.width==0||window.height==0{return Ok(());}
        let error=unsafe{ffi::xcb_request_check(self.conn,ffi::xcb_map_window_checked(self.conn,window.xid))};
        if !error.is_null(){unsafe{libc::free(error as *mut _);}return Err(BackendError::X11);}
        // Rendering into an unmapped window does not retain its server pixels.
        // Replay before acknowledgement; a WM-delayed map still repaints on Expose.
        let damage=window.last_frame.as_ref().filter(|f|f.width==window.width&&f.height==window.height)
            .map(|f|Rect{left:0,top:0,right:f.width as i32,bottom:f.height as i32});
        if let Some(damage)=damage{self.repaint(hwnd,damage)?;}
        Ok(())
    }
}
