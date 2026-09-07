//! Presentation only: derive each XOR overlay from unmodified HWND backing pixels.
use crate::TransportError;
use syscall::nt_compositor::caret::Snapshot;
/// A caret overlay's coverage, in the backing surface's own coordinates.
pub(crate) type Bounds=crate::Rect;
/// Coverage of an overlay that is drawn nowhere.
const EMPTY:Bounds=Bounds{left:0,top:0,right:0,bottom:0};

/// Coverage of both, so a caret that moved erases where it was and draws
/// where it is in one repaint. # C: O(1)
fn union(a:Option<Bounds>,b:Option<Bounds>)->Option<Bounds>{
    match (a,b){
        (Some(a),Some(b))=>Some(Bounds{left:a.left.min(b.left),top:a.top.min(b.top),right:a.right.max(b.right),bottom:a.bottom.max(b.bottom)}),
        (one,None)|(None,one)=>one,
    }
}

#[derive(Default)]
pub(crate) struct Surface {snapshot:Option<Snapshot>}
impl Surface {
    /// Equal-generation erase/paint is stream-ordered; older transactions cannot resurrect an image.
    /// `None` is a snapshot that did not take effect. An accepted one reports
    /// the coverage it alters - where the overlay was and where it now is -
    /// which is empty when neither is drawn.
    pub(crate) fn update(&mut self,snapshot:Snapshot)->Result<Option<Bounds>,TransportError>{
        snapshot.validate().map_err(|_|TransportError::InvalidFrame)?;
        if self.snapshot.as_ref().is_some_and(|old|old.generation>snapshot.generation||old==&snapshot){return Ok(None);}
        let before=self.covered();
        self.snapshot=Some(snapshot);
        Ok(Some(union(before,self.covered()).unwrap_or(EMPTY)))
    }

    /// Where this surface currently draws, if anywhere. # C: O(1)
    pub(crate) fn covered(&self)->Option<Bounds>{
        let s=self.snapshot.as_ref().filter(|s|s.visible)?;
        Some(Bounds{left:s.rect.x,top:s.rect.y,right:s.rect.x.saturating_add(s.rect.width as i32),
            bottom:s.rect.y.saturating_add(s.rect.height as i32)})
    }
    /// The value one surface pixel is XORed with, or zero where the overlay
    /// draws nothing. The overlay is presentation only: it is read while the
    /// damaged pixels are assembled for the display, so the retained surface
    /// keeps the pristine pixels the application drew and no copy of it is
    /// made to hold a composite. # C: O(1)
    pub(crate) fn xor_at(&self,x:i32,y:i32)->u32{
        let Some(s)=self.snapshot.as_ref().filter(|s|s.visible)else{return 0;};
        let (Some(dx),Some(dy))=(x.checked_sub(s.rect.x),y.checked_sub(s.rect.y))else{return 0;};
        if dx<0||dy<0||dx as i64>=s.rect.width as i64||dy as i64>=s.rect.height as i64{return 0;}
        s.mask.get(dy as usize*s.rect.width as usize+dx as usize).copied().unwrap_or(0)
    }
}
#[cfg(test)]
#[path="tests/caret.rs"]mod tests;
