//! Presentation only: derive each XOR overlay from unmodified HWND backing pixels.
use crate::{Frame,TransportError};
use std::borrow::Cow;
use syscall::nt_compositor::caret::Snapshot;
#[derive(Default)]
pub(crate) struct Surface {snapshot:Option<Snapshot>}
impl Surface {
    /// Equal-generation erase/paint is stream-ordered; older transactions cannot resurrect an image.
    pub(crate) fn update(&mut self,snapshot:Snapshot)->Result<bool,TransportError>{
        snapshot.validate().map_err(|_|TransportError::InvalidFrame)?;
        if self.snapshot.as_ref().is_some_and(|old|old.generation>snapshot.generation||old==&snapshot){return Ok(false);}
        self.snapshot=Some(snapshot);Ok(true)
    }
    /// Output is disposable presentation pixels. Caller never replaces the pristine base with these.
    pub(crate) fn compose<'a>(&self,base:&'a Frame)->Result<Cow<'a,[u32]>,TransportError>{
        let n=(base.stride as usize).checked_mul(base.height as usize).ok_or(TransportError::InvalidFrame)?;
        if base.width==0||base.height==0||base.stride<base.width||n>crate::protocol::MAX_PIXELS||n!=base.pixels.len(){return Err(TransportError::InvalidFrame);}
        let Some(s)=self.snapshot.as_ref().filter(|s|s.visible)else{return Ok(Cow::Borrowed(&base.pixels));};
        let x0=(s.rect.x as i64).max(0);let y0=(s.rect.y as i64).max(0);
        let x1=(s.rect.x as i64+s.rect.width as i64).min(base.width as i64);
        let y1=(s.rect.y as i64+s.rect.height as i64).min(base.height as i64);
        if x0>=x1||y0>=y1{return Ok(Cow::Borrowed(&base.pixels));}
        let mut out=Vec::new();out.try_reserve_exact(n).map_err(|_|TransportError::InvalidFrame)?;out.extend_from_slice(&base.pixels);
        for y in y0..y1{for x in x0..x1{
            let src=(y-s.rect.y as i64) as usize*s.rect.width as usize+(x-s.rect.x as i64) as usize;
            let dst=y as usize*base.stride as usize+x as usize;
            out[dst]^=s.mask[src];
        }}Ok(Cow::Owned(out))
    }
}
#[cfg(test)]
#[path="tests/caret.rs"]mod tests;
