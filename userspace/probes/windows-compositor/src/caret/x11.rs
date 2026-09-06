//! Caret snapshots reuse the existing HWND backing frame and checked X11 repaint path.
use super::*;
use syscall::nt_compositor::caret::Snapshot;
impl Backend {
    pub(super) fn update_caret(&mut self,hwnd:u32,snapshot:Snapshot)->Result<(),BackendError>{
        let damage={
            let window=self.windows.get_mut(&hwnd).ok_or(BackendError::InvalidCommand)?;
            if !window.caret.update(snapshot).map_err(BackendError::Transport)?{return Ok(());}
            window.last_frame.as_ref().map(|frame|Rect{left:0,top:0,right:frame.width as i32,bottom:frame.height as i32})
        };
        if let Some(damage)=damage{self.repaint(hwnd,damage)?;}Ok(())
    }
}
