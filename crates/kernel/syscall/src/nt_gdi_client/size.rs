//! DC metadata describes empty drawable coverage without invalidating the HDC.
use super::Error;
/// Nonnegative metadata extents, independent of pixel/frame admission. # C: O(1)
pub(super) fn dimensions(width:i32,height:i32)->Result<(),Error>{
    if width<0||height<0{Err(Error::Dimensions)}else{Ok(())}
}
/// Signed visible coordinates may be negative; extents must fit and be nonnegative. # C: O(1)
pub(super) fn visible_rect(left:i32,top:i32,right:i32,bottom:i32)->Result<(),Error>{
    dimensions(right.checked_sub(left).ok_or(Error::Dimensions)?,bottom.checked_sub(top).ok_or(Error::Dimensions)?)
}
#[cfg(test)]
#[path = "tests/size.rs"]
mod tests;
