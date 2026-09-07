//! World/page/device coordinate transforms; 31fk§8.
//!
//! The Win32 XFORM carries six 32-bit floats. Every arithmetic step is done in
//! double precision and only the stored matrix keeps single precision, so a
//! combined transform matches the source-of-record bit for bit.

/// Six-element affine matrix in the Win32 XFORM field order.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Xform { pub m11: f32, pub m12: f32, pub m21: f32, pub m22: f32, pub dx: f32, pub dy: f32 }

/// A logical or device coordinate pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct Point { pub x: i32, pub y: i32 }

/// A logical or device extent pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct Size { pub cx: i32, pub cy: i32 }

/// Below this magnitude a determinant counts as singular and the matrix has no inverse.
const SINGULAR_DETERMINANT: f64 = 1e-12;

impl Xform {
    /// The unit matrix a freshly initialised device context carries.
    pub const IDENTITY: Xform = Xform { m11: 1.0, m12: 0.0, m21: 0.0, m22: 1.0, dx: 0.0, dy: 0.0 };

    /// Matrix product in the order the source of record applies it: `first`
    /// then `second`, with the translation of `second` added last. # C: O(1)
    pub fn combine(first: &Xform, second: &Xform) -> Xform {
        let (a, b) = (first.wide(), second.wide());
        Xform::narrow([
            a[0] * b[0] + a[1] * b[2], a[0] * b[1] + a[1] * b[3],
            a[2] * b[0] + a[3] * b[2], a[2] * b[1] + a[3] * b[3],
            a[4] * b[0] + a[5] * b[2] + b[4], a[4] * b[1] + a[5] * b[3] + b[5],
        ])
    }

    /// The inverse matrix, or `None` when the 2x2 submatrix is singular. # C: O(1)
    pub fn invert(&self) -> Option<Xform> {
        let w = self.wide();
        let determinant = w[0] * w[3] - w[1] * w[2];
        if determinant > -SINGULAR_DETERMINANT && determinant < SINGULAR_DETERMINANT { return None; }
        let (m11, m12) = (w[3] / determinant, -w[1] / determinant);
        let (m21, m22) = (-w[2] / determinant, w[0] / determinant);
        Some(Xform::narrow([m11, m12, m21, m22,
            -w[4] * m11 - w[5] * m21, -w[4] * m12 - w[5] * m22]))
    }

    /// Map one point through the matrix with the rounding the mapping code uses. # C: O(1)
    pub fn apply(&self, point: Point) -> Point {
        let w = self.wide();
        let (x, y) = (f64::from(point.x), f64::from(point.y));
        Point { x: gdi_round(x * w[0] + y * w[2] + w[4]), y: gdi_round(x * w[1] + y * w[3] + w[5]) }
    }

    /// Compare only the 2x2 linear submatrix, which is what decides whether a
    /// font and pen must be reselected at their new size. # C: O(1)
    pub fn linear_eq(&self, other: &Xform) -> bool {
        self.m11 == other.m11 && self.m12 == other.m12 && self.m21 == other.m21 && self.m22 == other.m22
    }

    fn wide(&self) -> [f64; 6] {
        [f64::from(self.m11), f64::from(self.m12), f64::from(self.m21), f64::from(self.m22),
         f64::from(self.dx), f64::from(self.dy)]
    }

    fn narrow(values: [f64; 6]) -> Xform {
        Xform { m11: values[0] as f32, m12: values[1] as f32, m21: values[2] as f32,
            m22: values[3] as f32, dx: values[4] as f32, dy: values[5] as f32 }
    }

    /// Little-endian XFORM as a Win32 client reads it. # C: O(1)
    pub fn to_le_bytes(&self) -> [u8; XFORM_BYTES] {
        let mut bytes = [0u8; XFORM_BYTES];
        for (index, field) in [self.m11, self.m12, self.m21, self.m22, self.dx, self.dy].iter().enumerate() {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&field.to_le_bytes());
        }
        bytes
    }

    /// Decode a client-supplied XFORM. # C: O(1)
    pub fn from_le_bytes(bytes: &[u8; XFORM_BYTES]) -> Xform {
        let field = |index: usize| f32::from_le_bytes([bytes[index * 4], bytes[index * 4 + 1], bytes[index * 4 + 2], bytes[index * 4 + 3]]);
        Xform { m11: field(0), m12: field(1), m21: field(2), m22: field(3), dx: field(4), dy: field(5) }
    }
}

/// Six single-precision fields.
pub const XFORM_BYTES: usize = 24;

/// Round a transformed coordinate the way the mapping code does: the largest
/// integer not greater than the value plus one half, saturating at the signed
/// 32-bit range rather than wrapping. # C: O(1)
pub fn gdi_round(value: f64) -> i32 {
    let shifted = value + 0.5;
    if !(shifted > f64::from(i32::MIN)) { return i32::MIN; }
    if !(shifted < f64::from(i32::MAX)) { return i32::MAX; }
    let truncated = shifted as i64 as f64;
    (if shifted < truncated { truncated - 1.0 } else { truncated }) as i32
}

/// Scale rounding to nearest, away from zero, reporting -1 on a zero divisor or
/// an out-of-range result. The mapping modes derive every metric extent with it. # C: O(1)
pub fn muldiv(a: i32, b: i32, c: i32) -> i32 {
    if c == 0 { return -1; }
    let (a, c) = if c < 0 { (-i64::from(a), -i64::from(c)) } else { (i64::from(a), i64::from(c)) };
    let product = a * i64::from(b);
    let ret = if product >= 0 { (product + c / 2) / c } else { (product - c / 2) / c };
    if ret > i64::from(i32::MAX) || ret < -i64::from(i32::MAX) { return -1; }
    ret as i32
}

#[cfg(test)]
#[path = "tests/xform.rs"]
mod tests;
