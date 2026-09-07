//! Integer ellipse, arc and rounded-rectangle point runs.
use alloc::vec::Vec;
use super::{GdiError, Point, Rect};
use crate::win32_gdi::AD_CLOCKWISE;

/// Points on the first quadrant of an ellipse inscribed in `width` by
/// `height`, running counterclockwise from the x axis. An empty extent has no
/// points at all. # C: O(width + height)
pub fn ellipse_first_quadrant(width: i32, height: i32) -> Result<Vec<Point>, GdiError> {
    let mut data = Vec::new();
    if width <= 0 || height <= 0 { return Ok(data); }
    let (a, b) = (i64::from(width) - 1, i64::from(height) - 1);
    let (asq, bsq) = (8 * a * a, 8 * b * b);
    let odd = b % 2;
    let mut dx = 4 * b * b * (1 - a);
    let mut dy = 4 * a * a * (1 + odd);
    let mut err = dx + dy + a * a * odd;
    let mut point = Point { x: width - 1, y: height / 2 };
    // Every step moves one pixel along a monotone quadrant arc, so the run is
    // bounded by the semi-perimeter of the bounding box.
    data.try_reserve((width as usize + height as usize) / 2 + 2).map_err(|_| GdiError::HandleLimit)?;
    while i64::from(point.x) >= i64::from(width / 2) {
        if data.len() == data.capacity() { data.try_reserve(1).map_err(|_| GdiError::HandleLimit)?; }
        data.push(point);
        let e2 = 2 * err;
        if e2 >= dx { point.x -= 1; dx += bsq; err += dx; }
        if e2 <= dy { point.y += 1; dy += asq; err += dy; }
    }
    Ok(data)
}

/// Index of the first quadrant point at or past the ray through `(x, y)`,
/// mapped into the four-quadrant run. # C: O(N_quadrant_points)
fn find_intersection(points: &[Point], x: i32, y: i32, count: usize) -> usize {
    let (x, y) = (i64::from(x), i64::from(y));
    let scan = |compare: &dyn Fn(i64, i64) -> bool| -> usize {
        points.iter().take(count).position(|p| compare(i64::from(p.x), i64::from(p.y))).unwrap_or(count)
    };
    if y >= 0 {
        if x >= 0 { return scan(&|px, py| px * y <= py * x); }
        return 2 * count - scan(&|px, py| px * y < py * -x);
    }
    if x >= 0 { return 4 * count - scan(&|px, py| px * -y <= py * x); }
    2 * count + scan(&|px, py| px * -y < py * -x)
}

/// The device-space point run of the arc from `start` to `end` around the
/// ellipse inscribed in `rect`, swept in the given direction. # C: O(width + height)
pub fn arc_points(arc_dir: u32, rect: Rect, start: Point, end: Point) -> Result<Vec<Point>, GdiError> {
    let width = rect.right - rect.left;
    let height = rect.bottom - rect.top;
    let mut quadrant = ellipse_first_quadrant(width, height)?;
    let count = quadrant.len();
    if count == 0 { return Ok(Vec::new()); }
    for point in quadrant.iter_mut() { point.x -= width / 2; point.y -= height / 2; }
    let (start, end) = if arc_dir != AD_CLOCKWISE {
        (Point { x: start.x, y: start.y.saturating_neg() }, Point { x: end.x, y: end.y.saturating_neg() })
    } else { (start, end) };
    let start_pos = find_intersection(&quadrant, start.x, start.y, count);
    let mut end_pos = find_intersection(&quadrant, end.x, end.y, count);
    if end_pos <= start_pos { end_pos += 4 * count; }
    let mut out = Vec::new();
    out.try_reserve(end_pos - start_pos).map_err(|_| GdiError::HandleLimit)?;
    let (left, top) = (rect.left + width / 2, rect.top + height / 2);
    let (right, bottom) = (rect.right - 1 - width / 2, rect.bottom - 1 - height / 2);
    for i in start_pos..end_pos {
        let forward = quadrant[i % count];
        let mirrored = quadrant[count - 1 - i % count];
        out.push(match ((i / count) % 4, arc_dir == AD_CLOCKWISE) {
            (0, true) => Point { x: left + forward.x, y: top + forward.y },
            (1, true) => Point { x: right - mirrored.x, y: top + mirrored.y },
            (2, true) => Point { x: right - forward.x, y: bottom - forward.y },
            (_, true) => Point { x: left + mirrored.x, y: bottom - mirrored.y },
            (0, false) => Point { x: left + forward.x, y: bottom - forward.y },
            (1, false) => Point { x: right - mirrored.x, y: bottom - mirrored.y },
            (2, false) => Point { x: right - forward.x, y: top + forward.y },
            (_, false) => Point { x: left + mirrored.x, y: top + mirrored.y },
        });
    }
    Ok(out)
}

/// The closed device-space outline of a rounded rectangle, built from one
/// quadrant mirrored horizontally and then vertically. # C: O(ellipse extent)
pub fn round_rect_points(rect: Rect, ellipse_width: i32, ellipse_height: i32, arc_dir: u32)
    -> Result<Vec<Point>, GdiError> {
    let mut points = ellipse_first_quadrant(ellipse_width, ellipse_height)?;
    let mut count = points.len();
    if count == 0 { return Ok(points); }
    for point in points.iter_mut() {
        point.x = rect.right - ellipse_width + point.x;
        point.y = if arc_dir == AD_CLOCKWISE { rect.bottom - ellipse_height + point.y }
            else { rect.top + ellipse_height - 1 - point.y };
    }
    for (horizontal, span, extent) in [(true, rect.right - rect.left, ellipse_width),
                                       (false, rect.bottom - rect.top, ellipse_height)] {
        // The mirrored half repeats the midpoint whenever the ellipse spans
        // the whole side with an odd extent.
        let mut end = 2 * count - 1;
        if extent % 2 != 0 && extent == span { end -= 1; }
        if end + 1 > points.len() {
            points.try_reserve(end + 1 - points.len()).map_err(|_| GdiError::HandleLimit)?;
            points.resize(end + 1, Point { x: 0, y: 0 });
        }
        for i in 0..count {
            points[end - i] = if horizontal {
                Point { x: rect.left + rect.right - 1 - points[i].x, y: points[i].y }
            } else {
                Point { x: points[i].x, y: rect.top + rect.bottom - 1 - points[i].y }
            };
        }
        count = end + 1;
    }
    points.truncate(count);
    Ok(points)
}

#[cfg(test)]
#[path = "tests/geometry.rs"]
mod tests;
