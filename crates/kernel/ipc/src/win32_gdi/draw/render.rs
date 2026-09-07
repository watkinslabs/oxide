//! Device-context entry points that stroke and fill the geometric point runs.
use alloc::vec::Vec;
use super::{GdiError, GdiManager, Point, Rect};
use super::{arc_points, round_rect_points, flatten_bezier, WINDING};
use crate::win32_gdi::{DcAttr, LAYOUT_RTL, GM_ADVANCED};

/// Draw the arc alone.
pub const ARC: u32 = 0;
/// Draw the arc and join it to the current position, which then moves to the end.
pub const ARC_TO: u32 = 1;
/// Close the arc with a chord across its endpoints.
pub const CHORD: u32 = 2;
/// Close the arc through the centre of the ellipse.
pub const PIE: u32 = 3;

/// Draw one or more closed filled polygons.
pub const POLY_POLYGON: u32 = 1;
/// Draw one or more open polylines.
pub const POLY_POLYLINE: u32 = 2;
/// Draw cubic curves from an absolute run.
pub const POLY_BEZIER: u32 = 3;
/// Draw cubic curves starting at the current position.
pub const POLY_BEZIER_TO: u32 = 4;
/// Draw a polyline starting at the current position.
pub const POLYLINE_TO: u32 = 5;
/// Build a region from the polygons rather than drawing them.
pub const POLY_POLYGON_RGN: u32 = 6;

pub use crate::win32_gdi::path::{PT_BEZIERTO, PT_CLOSEFIGURE, PT_LINETO, PT_MOVETO};

impl GdiManager {
    /// The device rectangle a bounded primitive covers. Right-to-left layout
    /// shifts the rectangle left before mapping so the right border survives
    /// the mirror. An empty rectangle draws nothing. # C: O(DCs)
    fn device_rect(attr: &DcAttr, rect: Rect) -> Option<Rect> {
        let shift = i32::from(attr.layout & LAYOUT_RTL != 0);
        let top_left = attr.lp_to_dp(Point { x: rect.left - shift, y: rect.top });
        let bottom_right = attr.lp_to_dp(Point { x: rect.right - shift, y: rect.bottom });
        let ordered = Rect {
            left: top_left.x.min(bottom_right.x), top: top_left.y.min(bottom_right.y),
            right: top_left.x.max(bottom_right.x), bottom: top_left.y.max(bottom_right.y) };
        if ordered.left == ordered.right || ordered.top == ordered.bottom { None } else { Some(ordered) }
    }

    /// Paint the interior first, then stroke the outline over it, which is the
    /// order a cosmetic pen requires so the outline is never clipped away.
    /// # C: O(DCs + objects + clipped area)
    fn draw_run(&mut self, dc: u32, points: &[Point], close: bool, fill: bool) -> Result<(), GdiError> {
        if points.len() < 2 { return Ok(()); }
        let shared = self.pen_raster_state(dc)?;
        if fill { self.brush_polygon(dc, points, WINDING, Some(shared))?; }
        let mut segments: Vec<(i32, i32)> = Vec::new();
        segments.try_reserve(points.len()).map_err(|_| GdiError::HandleLimit)?;
        for point in points { segments.push((point.x, point.y)); }
        self.pen_polyline(dc, &segments, close, Some(shared))?;
        self.accumulate_run_bounds(dc, points)
    }

    fn accumulate_run_bounds(&mut self, dc: u32, points: &[Point]) -> Result<(), GdiError> {
        let mut bounds = crate::win32_gdi::empty_bounds();
        for point in points {
            crate::win32_gdi::add_bounds_rect(&mut bounds, &Rect { left: point.x, top: point.y,
                right: point.x.saturating_add(1), bottom: point.y.saturating_add(1) });
        }
        let index = self.dcs.iter().position(|(handle, _)| *handle == dc).ok_or(GdiError::NoSuchObject)?;
        self.dcs[index].1.attr.accumulate_bounds(bounds);
        Ok(())
    }

    /// Draw the ellipse inscribed in a logical rectangle. It is the rounded
    /// rectangle whose corner ellipse spans the whole rectangle. # C: O(area)
    pub fn ellipse(&mut self, dc: u32, rect: Rect) -> Result<(), GdiError> {
        self.round_rect(dc, rect, rect.right - rect.left, rect.bottom - rect.top)
    }

    /// Draw a rounded rectangle. A corner ellipse of two pixels or less in
    /// either direction degenerates to a plain rectangle. # C: O(area)
    pub fn round_rect(&mut self, dc: u32, rect: Rect, ellipse_width: i32, ellipse_height: i32)
        -> Result<(), GdiError> {
        let attr = self.dc_attr(dc)?;
        let Some(device) = Self::device_rect(&attr, rect) else { return Ok(()); };
        let origin = attr.lp_to_dp(Point { x: 0, y: 0 });
        let corner = attr.lp_to_dp(Point { x: ellipse_width, y: ellipse_height });
        let ellipse_width = (device.right - device.left).min((corner.x - origin.x).saturating_abs());
        let ellipse_height = (device.bottom - device.top).min((corner.y - origin.y).saturating_abs());
        if ellipse_width <= 2 || ellipse_height <= 2 { return self.rectangle(dc, rect); }
        let points = round_rect_points(Rect { right: device.right, bottom: device.bottom, ..device },
            ellipse_width, ellipse_height, attr.arc_direction)?;
        self.draw_run(dc, &points, true, true)
    }

    /// Draw a rectangle through the existing rectangle primitive, which owns
    /// the pen and brush interaction for straight edges. # C: O(area)
    pub fn rectangle(&mut self, dc: u32, rect: Rect) -> Result<(), GdiError> {
        let attr = self.dc_attr(dc)?;
        if attr.graphics_mode == GM_ADVANCED {
            // An advanced-mode rectangle is a four-point polygon, so a rotating
            // world transform rotates it instead of re-ordering its corners.
            let corners = [Point { x: rect.left, y: rect.top }, Point { x: rect.right, y: rect.top },
                Point { x: rect.right, y: rect.bottom }, Point { x: rect.left, y: rect.bottom }];
            return self.poly_poly_draw(dc, &corners, &[4], POLY_POLYGON);
        }
        let Some(device) = Self::device_rect(&attr, rect) else { return Ok(()); };
        self.pen_rectangle(dc, device, None)?;
        let index = self.dcs.iter().position(|(handle, _)| *handle == dc).ok_or(GdiError::NoSuchObject)?;
        self.dcs[index].1.attr.accumulate_bounds(device);
        Ok(())
    }

    /// Draw one of the four arc forms. `ARC_TO` also moves the current position
    /// to the arc's end. # C: O(width + height + area)
    pub fn arc_internal(&mut self, dc: u32, kind: u32, rect: Rect, start: Point, end: Point)
        -> Result<(), GdiError> {
        if kind > PIE { return Err(GdiError::InvalidDimensions); }
        let attr = self.dc_attr(dc)?;
        let Some(device) = Self::device_rect(&attr, rect) else { return Ok(()); };
        let width = device.right - device.left;
        let height = device.bottom - device.top;
        let centre = Point { x: device.left + width / 2, y: device.top + height / 2 };
        let start_device = attr.lp_to_dp(start);
        let end_device = attr.lp_to_dp(end);
        let relative = |point: Point| Point { x: point.x - centre.x, y: point.y - centre.y };
        let mut points = Vec::new();
        if kind == ARC_TO {
            let position = self.text_state(dc)?.attributes.current_position;
            points.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
            points.push(attr.lp_to_dp(Point { x: position.0, y: position.1 }));
        }
        let arc = arc_points(attr.arc_direction, device, relative(start_device), relative(end_device))?;
        points.try_reserve(arc.len() + 1).map_err(|_| GdiError::HandleLimit)?;
        points.extend_from_slice(&arc);
        if kind == PIE { points.push(centre); }
        if points.len() < 2 { return Ok(()); }
        let closed = kind == CHORD || kind == PIE;
        self.draw_run(dc, &points, closed, closed)?;
        if kind == ARC_TO {
            if let Some(last) = points.last().copied() {
                let logical = attr.dp_to_lp(last);
                self.set_text_position(dc, (logical.x, logical.y))?;
            }
        }
        Ok(())
    }

    /// Draw an arc of `sweep` degrees starting at `start` degrees around a
    /// circle of the given radius, then move the current position to its end.
    /// A negative radius is refused. # C: O(radius)
    pub fn angle_arc(&mut self, dc: u32, centre: Point, radius: i32, start: f32, sweep: f32)
        -> Result<(), GdiError> {
        if radius < 0 { return Err(GdiError::InvalidDimensions); }
        let attr = self.dc_attr(dc)?;
        let point_at = |degrees: f64| {
            let (cos, sin) = cos_sin(degrees * core::f64::consts::PI / 180.0);
            Point { x: crate::win32_gdi::gdi_round(f64::from(centre.x) + cos * f64::from(radius)),
                y: crate::win32_gdi::gdi_round(f64::from(centre.y) - sin * f64::from(radius)) }
        };
        let first = point_at(f64::from(start));
        let last = point_at(f64::from(start) + f64::from(sweep));
        let rect = Rect { left: centre.x - radius, top: centre.y - radius,
            right: centre.x + radius, bottom: centre.y + radius };
        let previous = attr.arc_direction;
        self.set_arc_direction(dc, if sweep >= 0.0 { crate::win32_gdi::AD_COUNTERCLOCKWISE } else { crate::win32_gdi::AD_CLOCKWISE })?;
        let result = self.arc_internal(dc, ARC_TO, rect, first, last);
        self.set_arc_direction(dc, previous)?;
        result?;
        self.set_text_position(dc, (last.x, last.y))?;
        Ok(())
    }

    /// Set the arc sweep direction. # C: O(DCs)
    pub fn set_arc_direction(&mut self, dc: u32, direction: u32) -> Result<u32, GdiError> {
        let index = self.dcs.iter().position(|(handle, _)| *handle == dc).ok_or(GdiError::NoSuchObject)?;
        let previous = self.dcs[index].1.attr.arc_direction;
        self.dcs[index].1.attr.arc_direction = direction;
        Ok(previous)
    }

    /// Draw a run of line and curve segments described by a parallel type
    /// array, then move the current position to the last point. # C: O(N_points)
    pub fn poly_draw(&mut self, dc: u32, points: &[Point], types: &[u8]) -> Result<(), GdiError> {
        if points.len() != types.len() { return Err(GdiError::InvalidDimensions); }
        validate_poly_draw(types)?;
        let attr = self.dc_attr(dc)?;
        let position = self.text_state(dc)?.attributes.current_position;
        let mut run: Vec<Point> = Vec::new();
        run.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
        run.push(attr.lp_to_dp(Point { x: position.0, y: position.1 }));
        let mut index = 0;
        while index < points.len() {
            match types[index] & !PT_CLOSEFIGURE {
                PT_MOVETO => {
                    if run.len() >= 2 { self.draw_run(dc, &run, false, false)?; }
                    run.clear();
                    run.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
                    run.push(attr.lp_to_dp(points[index]));
                }
                PT_BEZIERTO => {
                    let mut control = Vec::new();
                    control.try_reserve(4).map_err(|_| GdiError::HandleLimit)?;
                    control.push(*run.last().ok_or(GdiError::InvalidDimensions)?);
                    for offset in 0..3 { control.push(attr.lp_to_dp(points[index + offset])); }
                    let flattened = flatten_bezier(&control)?;
                    run.try_reserve(flattened.len()).map_err(|_| GdiError::HandleLimit)?;
                    run.extend_from_slice(&flattened[1..]);
                    index += 2;
                }
                _ => {
                    run.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
                    run.push(attr.lp_to_dp(points[index]));
                }
            }
            if types[index] & PT_CLOSEFIGURE != 0 {
                let first = run[0];
                run.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
                run.push(first);
            }
            index += 1;
        }
        if run.len() >= 2 { self.draw_run(dc, &run, false, false)?; }
        if let Some(last) = points.last() { self.set_text_position(dc, (last.x, last.y))?; }
        Ok(())
    }

    /// Draw several point runs at once. Polygon runs are closed and filled;
    /// polyline runs are open. The curve forms accept exactly one run and move
    /// the current position to its last point. # C: O(N_points + area)
    pub fn poly_poly_draw(&mut self, dc: u32, points: &[Point], counts: &[u32], function: u32)
        -> Result<(), GdiError> {
        let attr = self.dc_attr(dc)?;
        let total: u64 = counts.iter().map(|count| u64::from(*count)).sum();
        if total != points.len() as u64 { return Err(GdiError::InvalidDimensions); }
        match function {
            POLY_POLYGON | POLY_POLYLINE => {
                let mut offset = 0usize;
                for count in counts {
                    let run = &points[offset..offset + *count as usize];
                    offset += *count as usize;
                    let mut device = Vec::new();
                    device.try_reserve(run.len()).map_err(|_| GdiError::HandleLimit)?;
                    for point in run { device.push(attr.lp_to_dp(*point)); }
                    let polygon = function == POLY_POLYGON;
                    self.draw_run(dc, &device, polygon, polygon)?;
                }
                Ok(())
            }
            POLY_BEZIER | POLY_BEZIER_TO | POLYLINE_TO => {
                if counts.len() != 1 { return Err(GdiError::InvalidDimensions); }
                let count = counts[0] as usize;
                let admitted = match function {
                    POLY_BEZIER => count != 1 && count % 3 == 1,
                    POLY_BEZIER_TO => count != 0 && count % 3 == 0,
                    _ => true,
                };
                if !admitted { return Err(GdiError::InvalidDimensions); }
                let position = self.text_state(dc)?.attributes.current_position;
                let mut device = Vec::new();
                device.try_reserve(count + 1).map_err(|_| GdiError::HandleLimit)?;
                if function != POLY_BEZIER { device.push(attr.lp_to_dp(Point { x: position.0, y: position.1 })); }
                for point in points { device.push(attr.lp_to_dp(*point)); }
                let run = if function == POLYLINE_TO { device } else { flatten_bezier(&device)? };
                self.draw_run(dc, &run, false, false)?;
                if let Some(last) = points.last() { self.set_text_position(dc, (last.x, last.y))?; }
                Ok(())
            }
            _ => Err(GdiError::InvalidDimensions),
        }
    }
}

/// A type array admits a move, a line with or without a close, or exactly
/// three curve points of which only the last may close the figure. # C: O(N_types)
fn validate_poly_draw(types: &[u8]) -> Result<(), GdiError> {
    let mut index = 0;
    while index < types.len() {
        match types[index] {
            PT_MOVETO | PT_LINETO | PT_LINETO_CLOSE => {}
            PT_BEZIERTO => {
                if index + 2 >= types.len() { return Err(GdiError::InvalidDimensions); }
                if types[index + 1] != PT_BEZIERTO { return Err(GdiError::InvalidDimensions); }
                if types[index + 2] & !PT_CLOSEFIGURE != PT_BEZIERTO { return Err(GdiError::InvalidDimensions); }
                index += 2;
            }
            _ => return Err(GdiError::InvalidDimensions),
        }
        index += 1;
    }
    Ok(())
}

const PT_LINETO_CLOSE: u8 = PT_LINETO | PT_CLOSEFIGURE;

/// Cosine and sine of an angle in radians, by range reduction onto a Taylor
/// series over a quarter turn. No floating-point library is linked into the
/// kernel, so the two arc primitives derive their own. # C: O(1)
fn cos_sin(radians: f64) -> (f64, f64) {
    let turn = 2.0 * core::f64::consts::PI;
    let mut angle = radians - turn * trunc(radians / turn);
    if angle < 0.0 { angle += turn; }
    let quadrant = trunc(angle / (core::f64::consts::PI / 2.0)) as i32 % 4;
    let reduced = angle - f64::from(quadrant) * (core::f64::consts::PI / 2.0);
    let (cos, sin) = (taylor_cos(reduced), taylor_sin(reduced));
    match quadrant { 0 => (cos, sin), 1 => (-sin, cos), 2 => (-cos, -sin), _ => (sin, -cos) }
}

fn trunc(value: f64) -> f64 {
    if !(value.abs() < 9.0e15) { return value; }
    value as i64 as f64
}

/// Fourteen terms cover a quarter turn to the last bit of a double.
const TAYLOR_TERMS: u32 = 14;

fn taylor_sin(x: f64) -> f64 { taylor(x, 1) }
fn taylor_cos(x: f64) -> f64 { taylor(x, 0) }

fn taylor(x: f64, first_power: u32) -> f64 {
    let mut term = if first_power == 1 { x } else { 1.0 };
    let mut sum = term;
    let mut power = first_power;
    for _ in 0..TAYLOR_TERMS {
        term = -term * x * x / (f64::from(power + 1) * f64::from(power + 2));
        power += 2;
        sum += term;
    }
    sum
}

#[cfg(test)]
#[path = "tests/render.rs"]
mod tests;
