//! Bounded cosmetic line coverage; storage and clipping membership remain DcPixel owner work.
use crate::win32_gdi::{Rect,GdiError};

/// Skip offscreen major-axis steps arithmetically, preserving directed endpoint/tie semantics.
/// # C: O(visible major-axis span), independent of offscreen line length
pub(super) fn line(start:(i32,i32),end:(i32,i32),bounds:Rect,
    mut emit:impl FnMut(i32,i32,u64)->Result<(),GdiError>)->Result<(),GdiError> {
    let dx=i64::from(end.0)-i64::from(start.0);let dy=i64::from(end.1)-i64::from(start.1);
    let (ax,ay)=(dx.abs(),dy.abs());let xmajor=ax>ay;
    let (major,minor,origin,sign,low,high,bias)=if xmajor {
        (ax,ay,i64::from(start.0),dx.signum(),i64::from(bounds.left),i64::from(bounds.right),i64::from(dy<=0))
    }else{(ay,ax,i64::from(start.1),dy.signum(),i64::from(bounds.top),i64::from(bounds.bottom),i64::from(dx<=0))};
    if major==0 || bounds.left>=bounds.right || bounds.top>=bounds.bottom {return Ok(());}
    let (first,last)=if sign>0 {((low-origin).max(0),(high-origin).min(major))}
        else{((origin-high+1).max(0),(origin-low+1).min(major))};
    for step in first..last {
        let offset=((2*i128::from(minor)*i128::from(step)+i128::from(major-1+bias))/(2*i128::from(major))) as i64;
        let (x,y)=if xmajor {(i64::from(start.0)+dx.signum()*step,i64::from(start.1)+dy.signum()*offset)}
            else{(i64::from(start.0)+dx.signum()*offset,i64::from(start.1)+dy.signum()*step)};
        if x>=i64::from(bounds.left)&&x<i64::from(bounds.right)&&y>=i64::from(bounds.top)&&y<i64::from(bounds.bottom) {
            emit(x as i32,y as i32,step as u64)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path="../tests/coverage.rs"]
mod tests;
