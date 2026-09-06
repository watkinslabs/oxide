//! Create-window coordinates. Inputs come from canonical process/display owners.

const WS_CHILD: u32 = 0x40000000;
const WS_POPUP: u32 = 0x80000000;
const CW_USEDEFAULT: i32 = i32::MIN;
const CW_USEDEFAULT16: i32 = 0x8000;
const SW_SHOW: i32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Rect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Coordinates { pub x: i32, pub y: i32, pub width: i32, pub height: i32 }

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Defaults {
    pub work_area: Option<Rect>,
    pub position: Option<(i32, i32)>,
    pub size: Option<(i32, i32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error { MissingWorkArea, Arithmetic }

fn is_default(value: i32) -> bool { value == CW_USEDEFAULT || value == CW_USEDEFAULT16 }

fn default_size(low: i32, high: i32, position: i32) -> Result<i32, Error> {
    let extent = i64::from(high) - i64::from(low);
    if extent < 0 { return Err(Error::Arithmetic); }
    i32::try_from(extent * 3 / 4 - i64::from(position)).map_err(|_| Error::Arithmetic)
}

/// Resolve defaults before coordinate addition. The show command carried in
/// y is returned for the lifecycle owner; it is not a vertical coordinate.
/// # C: O(1) plus at most one lazy process/monitor query
pub(super) fn fix(style: u32, mut c: Coordinates, defaults: impl FnOnce() -> Defaults)
    -> Result<(Coordinates, i32), Error> {
    let mut show = SW_SHOW;
    if style & (WS_CHILD | WS_POPUP) != 0 {
        if is_default(c.x) { c.x = 0; c.y = 0; }
        if is_default(c.width) { c.width = 0; c.height = 0; }
        return Ok((c, show));
    }
    if !is_default(c.x) && !is_default(c.width) && !is_default(c.height) { return Ok((c, show)); }
    let d = defaults();
    if is_default(c.x) {
        if !is_default(c.y) { show = c.y; }
        let (x, y) = match d.position {
            Some(position) => position,
            None => { let work = d.work_area.ok_or(Error::MissingWorkArea)?; (work.left, work.top) }
        };
        c.x = x; c.y = y;
    }
    if is_default(c.width) {
        (c.width, c.height) = match d.size {
            Some(size) => size,
            None => { let work = d.work_area.ok_or(Error::MissingWorkArea)?;
                (default_size(work.left, work.right, c.x)?, default_size(work.top, work.bottom, c.y)?) }
        };
    } else if is_default(c.height) {
        let work = d.work_area.ok_or(Error::MissingWorkArea)?;
        c.height = default_size(work.top, work.bottom, c.y)?;
    }
    Ok((c, show))
}

/// Final rectangle after the lifecycle owner's min/max adjustment. Negative
/// sizes become zero; positive endpoint overflow saturates, never wraps.
/// # C: O(1)
pub(super) fn rect(c: Coordinates) -> Rect {
    Rect { left: c.x, top: c.y, right: c.x.saturating_add(c.width.max(0)),
        bottom: c.y.saturating_add(c.height.max(0)) }
}
