//! Retained images follow drawing into native descendants, without replaying
//! an ancestor's older pixels over independently painted child windows.
use super::{Backend,BackendError,Frame,Rect};

impl Backend {
    /// Prepare every affected native image before changing retained pixels.
    pub(super) fn retain_frame(&mut self,hwnd:u32,frame:&Frame)->Result<(),BackendError>{
        let window=self.windows.get(&hwnd).ok_or(BackendError::InvalidCommand)?;
        if (window.width,window.height)!=(frame.width,frame.height){return Err(BackendError::InvalidCommand);}
        let children=self.child_frames(hwnd,frame)?;
        self.prepare_surface(hwnd,frame.width,frame.height)?;
        for (id,patch) in &children{self.prepare_surface(*id,patch.width,patch.height)?;}
        self.windows.get_mut(&hwnd).and_then(|w|w.surface.as_mut()).ok_or(BackendError::InvalidCommand)?
            .apply(frame).map_err(BackendError::Transport)?;
        for (id,patch) in children{
            self.windows.get_mut(&id).and_then(|w|w.surface.as_mut()).ok_or(BackendError::InvalidCommand)?
                .apply(&patch).map_err(BackendError::Transport)?;
        }
        Ok(())
    }

    fn prepare_surface(&mut self,hwnd:u32,width:u32,height:u32)->Result<(),BackendError>{
        let window=self.windows.get_mut(&hwnd).ok_or(BackendError::InvalidCommand)?;
        if !window.surface.as_ref().is_some_and(|s|(s.width,s.height)==(width,height)){
            window.surface=Some(crate::retained::Retained::new(width,height).map_err(BackendError::Transport)?);
        }
        Ok(())
    }

    /// INCLUDE_INFERIORS writes visible descendants too. Retain those exact
    /// writes in their existing images; otherwise their next Expose restores
    /// pixels older than the parent-DC drawing. Hidden branches are untouched.
    fn child_frames(&self,hwnd:u32,frame:&Frame)->Result<Vec<(u32,Frame)>,BackendError>{
        let parent=self.windows.get(&hwnd).ok_or(BackendError::InvalidCommand)?;
        let mut pending=vec![(parent.xid,0i32,0i32,frame.damage)];
        let mut patches=Vec::new();
        while let Some((parent,x,y,clip))=pending.pop(){
            for (id,child) in self.windows.iter().filter(|(_,w)|w.parent==parent&&w.requested_visible){
                let left=x.checked_add(child.rect.left).ok_or(BackendError::InvalidCommand)?;
                let top=y.checked_add(child.rect.top).ok_or(BackendError::InvalidCommand)?;
                let right=left.checked_add(child.width as i32).ok_or(BackendError::InvalidCommand)?;
                let bottom=top.checked_add(child.height as i32).ok_or(BackendError::InvalidCommand)?;
                let cut=Rect{left:clip.left.max(left),top:clip.top.max(top),right:clip.right.min(right),bottom:clip.bottom.min(bottom)};
                if cut.left>=cut.right||cut.top>=cut.bottom{continue;}
                let width=(cut.right-cut.left)as usize;
                let start=(cut.left-frame.damage.left)as usize;
                let mut pixels=Vec::new();
                pixels.try_reserve_exact(width*(cut.bottom-cut.top)as usize).map_err(|_|BackendError::InvalidCommand)?;
                for row in cut.top..cut.bottom{
                    let source=frame.row((row-frame.damage.top)as usize).and_then(|r|r.get(start..start+width))
                        .ok_or(BackendError::InvalidCommand)?;
                    pixels.extend_from_slice(source);
                }
                let damage=Rect{left:cut.left-left,top:cut.top-top,right:cut.right-left,bottom:cut.bottom-top};
                let patch=Frame::new(child.width,child.height,width as u32,pixels,damage).map_err(BackendError::Transport)?;
                patches.push((*id,patch));
                pending.push((child.xid,left,top,cut));
            }
        }
        Ok(patches)
    }
}
