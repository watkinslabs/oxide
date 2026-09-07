//! Recorded path points and the stroke/figure state machine; 31fk§8.
//! Points are stored in device coordinates, matching what a path query returns.
use super::{Vec, GdiError};
use crate::win32_gdi::region::scan::Point;

pub const PT_CLOSEFIGURE: u8 = 0x01;
pub const PT_LINETO: u8 = 0x02;
pub const PT_BEZIERTO: u8 = 0x04;
pub const PT_MOVETO: u8 = 0x06;
const MAX_POINTS: usize = 1 << 16;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GdiPath { points: Vec<Point>, flags: Vec<u8>, new_stroke: bool, pos: Point }

impl GdiPath {
    /// Recording opens at the device-space current position. # C: O(1)
    pub fn open(pos: Point) -> Self { Self { points: Vec::new(), flags: Vec::new(), new_stroke: false, pos } }
    /// # C: O(1)
    pub fn len(&self) -> usize { self.points.len() }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.points.is_empty() }
    /// # C: O(1)
    pub fn points(&self) -> &[Point] { &self.points }
    /// # C: O(1)
    pub fn flags(&self) -> &[u8] { &self.flags }
    /// # C: O(1)
    pub fn position(&self) -> Point { self.pos }

    /// # C: O(1) amortized
    fn add(&mut self, point: Point, flag: u8) -> Result<(), GdiError> {
        if self.points.len() >= MAX_POINTS { return Err(GdiError::HandleLimit); }
        self.points.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
        self.flags.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
        self.points.push(point); self.flags.push(flag); Ok(())
    }

    /// A stroke continues only from an unclosed final point at the current position. # C: O(1)
    fn start_stroke(&mut self) -> Result<(), GdiError> {
        if !self.new_stroke && !self.points.is_empty()
            && self.flags[self.flags.len() - 1] & PT_CLOSEFIGURE == 0
            && self.points[self.points.len() - 1] == self.pos { return Ok(()); }
        self.new_stroke = false;
        let pos = self.pos;
        self.add(pos, PT_MOVETO)
    }

    /// Append one already-device-space entry, preserving its recorded flag. # C: O(1) amortized
    pub fn push_raw(&mut self, point: Point, flag: u8) -> Result<(), GdiError> { self.add(point, flag) }

    /// Move sets the next stroke origin without recording a point. # C: O(1)
    pub fn move_to(&mut self, point: Point) { self.new_stroke = true; self.pos = point; }

    /// Append points of one type, opening a stroke and advancing the position. # C: O(N_points)
    pub fn line_to(&mut self, points: &[Point], flag: u8) -> Result<(), GdiError> {
        if points.is_empty() { return Ok(()); }
        self.start_stroke()?;
        for point in points { self.add(*point, flag)?; }
        self.pos = self.points[self.points.len() - 1];
        Ok(())
    }

    /// Closed figures record a virtual closing edge on the last recorded point. # C: O(1)
    pub fn close_figure(&mut self) { if let Some(flag) = self.flags.last_mut() { *flag |= PT_CLOSEFIGURE; } }

    /// A rectangle is one closed four-point figure independent of the current position. # C: O(1)
    pub fn rectangle(&mut self, left: i32, top: i32, right: i32, bottom: i32, clockwise: bool) -> Result<(), GdiError> {
        let mut points = [Point { x: right, y: top }, Point { x: left, y: top },
            Point { x: left, y: bottom }, Point { x: right, y: bottom }];
        if clockwise { points.reverse(); }
        let first = self.points.len();
        for point in points { self.add(point, PT_LINETO)?; }
        self.flags[first] = PT_MOVETO;
        self.close_figure();
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/path_record.rs"]
mod tests;
