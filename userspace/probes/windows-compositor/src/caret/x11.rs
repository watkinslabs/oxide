//! Caret snapshots reuse the existing HWND backing frame and checked X11 repaint path.
use super::*;
use syscall::nt_compositor::caret::Snapshot;
impl Backend {
    pub(super) fn update_caret(&mut self,hwnd:u32,snapshot:Snapshot)->Result<(),BackendError>{
        // A blink alters the caret's own few pixels. Repainting the whole
        // window for it costs one server request per tile of that window,
        // twice a second, for every window that owns a caret.
        let damage={
            let window=self.windows.get_mut(&hwnd).ok_or(BackendError::InvalidCommand)?;
            let Some(changed)=window.caret.update(snapshot).map_err(BackendError::Transport)?else{return Ok(());};
            window.last_frame.as_ref().map(|frame|Rect{
                left:changed.left.max(0),top:changed.top.max(0),
                right:changed.right.min(frame.width as i32),bottom:changed.bottom.min(frame.height as i32)})
                .filter(|r|r.left<r.right&&r.top<r.bottom)
        };
        if let Some(damage)=damage{self.repaint(hwnd,damage)?;}Ok(())
    }
}
