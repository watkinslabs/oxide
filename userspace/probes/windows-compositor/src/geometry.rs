#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }

impl Rect {
    pub fn is_inside(self, width: u32, height: u32) -> bool {
        self.left >= 0 && self.top >= 0 && self.right > self.left && self.bottom > self.top
            && u32::try_from(self.right).ok().is_some_and(|v| v <= width)
            && u32::try_from(self.bottom).ok().is_some_and(|v| v <= height)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorSnapshot {
    pub desktop: u32,
    pub monitor: Rect,
    pub work_area: Rect,
}

pub fn decode_cardinals(values: &[u32]) -> Option<u32> { if values.len() == 1 { Some(values[0]) } else { None } }

pub fn decode_work_area(values: &[u32], desktop: u32) -> Option<Rect> {
    let offset = usize::try_from(desktop).ok()?.checked_mul(4)?;
    let v = values.get(offset..offset.checked_add(4)?)?;
    let left = i32::try_from(v[0]).ok()?;
    let top = i32::try_from(v[1]).ok()?;
    let width = i32::try_from(v[2]).ok()?;
    let height = i32::try_from(v[3]).ok()?;
    if width <= 0 || height <= 0 { return None; }
    Some(Rect { left, top, right: left.checked_add(width)?, bottom: top.checked_add(height)? })
}
