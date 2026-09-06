//! Exact resize damage derives from preservation destination and previously invalid source pixels.
use super::*;
impl WindowManager{
    pub(super) fn position_damage(&self,id:WindowId,p:WindowPosition,valid:Option<[WindowRect;2]>)->Result<PaintDamage,WindowError>{
        let old=self.rect(id).ok_or(WindowError::NoSuchWindow)?;
        let record=self.get(id).ok_or(WindowError::NoSuchWindow)?;
        let old_client=record.client_rect.unwrap_or(old);let client=p.client.or(record.client_rect).unwrap_or(p.rect);
        let local=local_rect(client,client)?;
        let mut next=self.erase_damage(id)?;
        let mut uncovered=PaintRegion::from_rect(local)?;
        if let Some([destination,source])=valid{
            let dst=local_rect(destination,client)?;let src=local_rect(source,old_client)?;
            let old_local=local_rect(old_client,old_client)?;
            let width=|r:WindowRect|r.right.checked_sub(r.left);let height=|r:WindowRect|r.bottom.checked_sub(r.top);
            if width(dst).is_none_or(|n|n<=0)||height(dst).is_none_or(|n|n<=0)||width(dst)!=width(src)||height(dst)!=height(src)||dst.left<0||dst.top<0||dst.right>local.right||dst.bottom>local.bottom
                ||src.left<0||src.top<0||src.right>old_local.right||src.bottom>old_local.bottom{return Err(WindowError::InvalidParent);}
            uncovered.subtract(&PaintRegion::from_rect(dst)?)?;
            let invalid=next.region.clipped(src)?.translated(dst.left.checked_sub(src.left).ok_or(WindowError::InvalidParent)?,dst.top.checked_sub(src.top).ok_or(WindowError::InvalidParent)?)?;
            uncovered.union(&invalid)?;
        }
        let resized=(old.right as i64-old.left as i64,old.bottom as i64-old.top as i64)!=(p.rect.right as i64-p.rect.left as i64,p.rect.bottom as i64-p.rect.top as i64);
        if next.nonclient||p.flags&FRAMECHANGED!=0||resized{
            let mut frame=PaintRegion::from_rect(local_rect(p.rect,client)?)?;frame.subtract(&PaintRegion::from_rect(local)?)?;
            uncovered.union(&frame)?;next.nonclient=!frame.is_empty();
        }
        next.region=uncovered;
        next.erase=!next.region.is_empty();if next.region.is_empty(){next.delayed_erase=false;next.nonclient=false;}
        Ok(next)
    }
}
fn local_rect(r:WindowRect,origin:WindowRect)->Result<WindowRect,WindowError>{
    let sub=|a:i32,b:i32|a.checked_sub(b).ok_or(WindowError::InvalidParent);
    Ok(WindowRect{left:sub(r.left,origin.left)?,top:sub(r.top,origin.top)?,right:sub(r.right,origin.left)?,bottom:sub(r.bottom,origin.top)?})
}
