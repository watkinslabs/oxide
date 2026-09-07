//! Glyph contours read from the face's own outline tables and emitted in the
//! two Windows polygon forms.
use super::super::native::font_height::{table, word};

const ON_CURVE: u8 = 0x01;
const X_SHORT: u8 = 0x02;
const Y_SHORT: u8 = 0x04;
const REPEAT: u8 = 0x08;
const X_SAME: u8 = 0x10;
const Y_SAME: u8 = 0x20;
const ARGS_ARE_WORDS: u16 = 0x0001;
const ARGS_ARE_XY: u16 = 0x0002;
const HAVE_SCALE: u16 = 0x0008;
const MORE_COMPONENTS: u16 = 0x0020;
const XY_SCALE: u16 = 0x0040;
const TWO_BY_TWO: u16 = 0x0080;
const MAX_COMPONENT_DEPTH: u32 = 5;
const SUBPIXEL_BITS: i64 = 6;
const SUBPIXEL_MASK: i64 = 0x3f;
pub(super) const TT_POLYGON_TYPE: u32 = 24;
pub(super) const TT_PRIM_LINE: u16 = 1;
pub(super) const TT_PRIM_QSPLINE: u16 = 2;
pub(super) const TT_PRIM_CSPLINE: u16 = 3;
const POINT_BYTES: usize = 8;

/// One glyph outline in subpixel units, with contour end indexes.
#[derive(Default, Clone)]
pub(super) struct Outline { pub points: Vec<(i64, i64)>, pub on_curve: Vec<bool>, pub contours: Vec<usize> }

fn short(bytes: &[u8], offset: usize) -> Option<i16> { Some(word(bytes, offset)? as i16) }

fn location(bytes: &[u8], glyph: u16) -> Option<(usize, usize)> {
    let long = short(table(bytes, b"head")?, 50)? != 0;
    let loca = table(bytes, b"loca")?;
    let index = usize::from(glyph);
    let (start, end) = if long {
        (u32::from_be_bytes(loca.get(index * 4..index * 4 + 4)?.try_into().ok()?) as usize,
         u32::from_be_bytes(loca.get(index * 4 + 4..index * 4 + 8)?.try_into().ok()?) as usize)
    } else {
        (usize::from(word(loca, index * 2)?) * 2, usize::from(word(loca, index * 2 + 2)?) * 2)
    };
    (end >= start).then_some((start, end))
}

/// Read one glyph's contours in design units, resolving component glyphs.
/// # C: O(points) per component
fn design(bytes: &[u8], glyph: u16, depth: u32) -> Option<Outline> {
    if depth > MAX_COMPONENT_DEPTH { return None; }
    let glyf = table(bytes, b"glyf")?;
    let (start, end) = location(bytes, glyph)?;
    if start == end { return Some(Outline::default()); }
    let data = glyf.get(start..end)?;
    let contours = short(data, 0)?;
    if contours < 0 { return composite(bytes, data, depth); }
    let contours = usize::try_from(contours).ok()?;
    let mut ends = Vec::with_capacity(contours);
    for index in 0..contours { ends.push(usize::from(word(data, 10 + index * 2)?)); }
    let count = ends.last().map(|last| last + 1).unwrap_or(0);
    let mut cursor = 10 + contours * 2;
    cursor += 2 + usize::from(word(data, cursor)?);
    let mut flags = Vec::with_capacity(count);
    while flags.len() < count {
        let flag = *data.get(cursor)?;
        cursor += 1;
        flags.push(flag);
        if flag & REPEAT != 0 {
            let repeat = *data.get(cursor)?;
            cursor += 1;
            for _ in 0..repeat { if flags.len() < count { flags.push(flag); } }
        }
    }
    let mut points = Vec::with_capacity(count);
    let mut value = 0i64;
    for flag in &flags {
        value += delta(data, &mut cursor, *flag, X_SHORT, X_SAME)?;
        points.push((value, 0));
    }
    value = 0;
    for (index, flag) in flags.iter().enumerate() {
        value += delta(data, &mut cursor, *flag, Y_SHORT, Y_SAME)?;
        points[index].1 = value;
    }
    Some(Outline { points, on_curve: flags.iter().map(|flag| flag & ON_CURVE != 0).collect(), contours: ends })
}

fn delta(data: &[u8], cursor: &mut usize, flag: u8, short_bit: u8, same_bit: u8) -> Option<i64> {
    if flag & short_bit != 0 {
        let value = i64::from(*data.get(*cursor)?);
        *cursor += 1;
        Some(if flag & same_bit != 0 { value } else { -value })
    } else if flag & same_bit != 0 { Some(0) } else {
        let value = i64::from(short(data, *cursor)?);
        *cursor += 2;
        Some(value)
    }
}

fn composite(bytes: &[u8], data: &[u8], depth: u32) -> Option<Outline> {
    let mut out = Outline::default();
    let mut cursor = 10;
    loop {
        let flags = word(data, cursor)?;
        let index = word(data, cursor + 2)?;
        cursor += 4;
        let (dx, dy) = if flags & ARGS_ARE_WORDS != 0 {
            let pair = (i64::from(short(data, cursor)?), i64::from(short(data, cursor + 2)?));
            cursor += 4;
            pair
        } else {
            let pair = (i64::from(*data.get(cursor)? as i8), i64::from(*data.get(cursor + 1)? as i8));
            cursor += 2;
            pair
        };
        if flags & HAVE_SCALE != 0 { cursor += 2; }
        else if flags & XY_SCALE != 0 { cursor += 4; }
        else if flags & TWO_BY_TWO != 0 { cursor += 8; }
        let component = design(bytes, index, depth + 1)?;
        let base = out.points.len();
        if flags & ARGS_ARE_XY != 0 {
            out.points.extend(component.points.iter().map(|(x, y)| (x + dx, y + dy)));
        } else { out.points.extend_from_slice(&component.points); }
        out.on_curve.extend_from_slice(&component.on_curve);
        out.contours.extend(component.contours.iter().map(|end| end + base));
        if flags & MORE_COMPONENTS == 0 { break; }
    }
    Some(out)
}

/// Scale one glyph's contours into subpixel units at the realized size. # C: O(points)
pub(super) fn outline(bytes: &[u8], glyph: u16, em: f32, ppem: f32) -> Option<Outline> {
    if em <= 0.0 || ppem <= 0.0 { return None; }
    let mut outline = design(bytes, glyph, 0)?;
    for point in &mut outline.points {
        let scale = |value: i64| ((value as f64) * f64::from(ppem) * 64.0 / f64::from(em)).round() as i64;
        *point = (scale(point.0), scale(point.1));
    }
    Some(outline)
}

fn point_bytes(point: (i64, i64)) -> [u8; POINT_BYTES] {
    let fixed = |value: i64| {
        let mut fract = ((value & SUBPIXEL_MASK) << 10) as u16;
        fract |= (fract >> 6) | (fract >> 12);
        let mut out = [0u8; 4];
        out[..2].copy_from_slice(&fract.to_le_bytes());
        out[2..].copy_from_slice(&((value >> SUBPIXEL_BITS) as i16).to_le_bytes());
        out
    };
    let mut bytes = [0u8; POINT_BYTES];
    bytes[..4].copy_from_slice(&fixed(point.0));
    bytes[4..].copy_from_slice(&fixed(point.1));
    bytes
}

fn header(out: &mut Vec<u8>, start: (i64, i64)) -> usize {
    let position = out.len();
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&point_bytes(start));
    position
}

fn curve(out: &mut Vec<u8>, kind: u16, points: &[(i64, i64)]) {
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(points.len() as u16).to_le_bytes());
    for point in points { out.extend_from_slice(&point_bytes(*point)); }
}

fn finish(out: &mut [u8], position: usize) {
    let length = (out.len() - position) as u32;
    out[position..position + 4].copy_from_slice(&length.to_le_bytes());
    out[position + 4..position + 8].copy_from_slice(&TT_POLYGON_TYPE.to_le_bytes());
}

/// Serialize the outline as quadratic polygons, adding the closing point that
/// Windows appends to a contour that ends on a control point. # C: O(points)
pub(super) fn native(outline: &Outline) -> Vec<u8> {
    let mut out = Vec::new();
    let mut point = 0usize;
    for end in &outline.contours {
        if point == *end { point += 1; continue; }
        let first = point;
        let position = header(&mut out, outline.points[point]);
        point += 1;
        while point <= *end {
            let kind = if outline.on_curve[point] { TT_PRIM_LINE } else { TT_PRIM_QSPLINE };
            let mut collected = Vec::new();
            loop {
                collected.push(outline.points[point]);
                point += 1;
                if point > *end || outline.on_curve[point] != outline.on_curve[point - 1] { break; }
            }
            if point > *end && !outline.on_curve[point - 1] { collected.push(outline.points[first]); }
            else if point <= *end && outline.on_curve[point] { collected.push(outline.points[point]); point += 1; }
            curve(&mut out, kind, &collected);
        }
        finish(&mut out, position);
    }
    out
}

/// Serialize the outline as cubic polygons, converting each quadratic segment
/// into the equivalent cubic control points. # C: O(points)
pub(super) fn bezier(outline: &Outline) -> Vec<u8> {
    let mut out = Vec::new();
    let mut point = 0usize;
    for end in &outline.contours {
        let first = point;
        let position = header(&mut out, outline.points[point]);
        point += 1;
        while point <= *end {
            let line = outline.on_curve[point];
            let kind = if line { TT_PRIM_LINE } else { TT_PRIM_CSPLINE };
            let mut collected = Vec::new();
            loop {
                if line { collected.push(outline.points[point]); point += 1; }
                else {
                    let mut start = outline.points[point - 1];
                    if !outline.on_curve[point - 1] { start = midpoint(start, outline.points[point]); }
                    let finish = if point + 1 > *end { outline.points[first] }
                        else if outline.on_curve[point + 1] { outline.points[point + 1] }
                        else { midpoint(outline.points[point + 1], outline.points[point]) };
                    let control = outline.points[point];
                    collected.push(third(control, start));
                    collected.push(third(control, finish));
                    collected.push(finish);
                    point += 1;
                }
                if point > *end || outline.on_curve[point] != outline.on_curve[point - 1] { break; }
            }
            if point <= *end && outline.on_curve[point] { point += 1; }
            curve(&mut out, kind, &collected);
        }
        finish(&mut out, position);
    }
    out
}

fn midpoint(a: (i64, i64), b: (i64, i64)) -> (i64, i64) { ((a.0 + b.0 + 1) >> 1, (a.1 + b.1 + 1) >> 1) }

fn third(control: (i64, i64), end: (i64, i64)) -> (i64, i64) {
    ((2 * control.0 + 1) / 3 + (end.0 + 1) / 3, (2 * control.1 + 1) / 3 + (end.1 + 1) / 3)
}

