//! 31gd: little-endian stream records; codecs use byte slices, never native layout.
extern crate alloc;
use alloc::vec::Vec;
pub mod caret;

pub const MAGIC: u32 = 0x4342584f;
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 32;
pub const MAX_PAYLOAD: usize = 32 * 1024 * 1024;
pub const MAX_QUEUED_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_QUEUED_RECORDS: usize = 64;
pub const SOCKET_CAP: usize = 256 * 1024;
pub const MAX_MONITORS: usize = 32;
pub const MAX_TITLE: usize = 4096;
pub const MAX_DIMENSION: u32 = 8192;
pub const PIXEL_BGRA8888: u32 = 1;

/// Payloads below list fields in wire order. Integers are little endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Opcode {
    /// i32 x,y; u32 width,height; u64 parent; u32 style,ex_style.
    Create = 1,
    /// Empty.
    Destroy = 2,
    /// u32 visible (0 or 1).
    Visibility = 3,
    /// UTF-8, no trailing NUL.
    Title = 4,
    /// i32 x,y; u32 width,height.
    Geometry = 5,
    /// u32 width,height,stride,format; stride*height owned pixel bytes.
    Frame = 6,
    /// u64 insertion; u32 flags (1 order, 2 activate); u32 reserved=0.
    Position = 7,
    /// Generation-stamped RGB-XOR caret snapshot.
    Caret = 8,
    /// u32 count; count records of Rect monitor, Rect workarea (each i32 x,y; u32 width,height).
    Monitors = 0x101,
    /// i32 x,y; u32 width,height.
    Configure = 0x102,
    /// u32 virtual_key, scan_code, pressed (0/1), modifiers.
    Key = 0x103,
    /// UTF-8 text.
    Text = 0x104,
    /// i32 x,y; u32 buttons; i32 wheel_delta.
    Pointer = 0x105,
    /// Empty: request WM_CLOSE; does not destroy the window.
    Close = 0x106,
    /// u32 status (0 success, nonzero backend failure); header sequence acknowledges one outbound record.
    Ack = 0x107,
    /// u32 active (0 deactivate, 1 activate); HWND identifies a top-level window.
    Focus = 0x108,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Header, Version, Opcode, Length, Payload, Overflow, Allocation }

pub const POSITION_ORDER: u32 = 1;
pub const POSITION_ACTIVATE: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header { pub opcode: Opcode, pub length: u32, pub sequence: u64, pub hwnd: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect { pub x: i32, pub y: i32, pub width: u32, pub height: u32 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Monitor { pub monitor: Rect, pub workarea: Rect }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record { pub header: Header, pub payload: Vec<u8> }

/// # C: O(1)
pub fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::Overflow)?;
    Ok(u32::from_le_bytes(bytes.get(offset..end).ok_or(Error::Length)?.try_into().map_err(|_| Error::Length)?))
}
/// # C: O(1)
pub fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let end = offset.checked_add(8).ok_or(Error::Overflow)?;
    Ok(u64::from_le_bytes(bytes.get(offset..end).ok_or(Error::Length)?.try_into().map_err(|_| Error::Length)?))
}

impl Opcode {
    /// # C: O(1)
    pub fn decode(value: u16) -> Result<Self, Error> {
        Ok(match value { 1 => Self::Create, 2 => Self::Destroy, 3 => Self::Visibility,
            4 => Self::Title, 5 => Self::Geometry, 6 => Self::Frame, 7 => Self::Position, 8 => Self::Caret, 0x101 => Self::Monitors,
            0x102 => Self::Configure, 0x103 => Self::Key, 0x104 => Self::Text,
            0x105 => Self::Pointer, 0x106 => Self::Close, 0x107 => Self::Ack, 0x108 => Self::Focus, _ => return Err(Error::Opcode) })
    }
    /// # C: O(1)
    pub fn from_backend(self) -> bool { (self as u16) >= Self::Monitors as u16 }
}

impl Header {
    /// Header bytes: magic:u32, version:u16, opcode:u16, length:u32,
    /// reserved:u32=0, sequence:u64, hwnd:u64. # C: O(1)
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != HEADER_LEN || u32_at(bytes, 0)? != MAGIC || u32_at(bytes, 12)? != 0 { return Err(Error::Header); }
        if u16::from_le_bytes([bytes[4], bytes[5]]) != VERSION { return Err(Error::Version); }
        let header = Self { opcode: Opcode::decode(u16::from_le_bytes([bytes[6], bytes[7]]))?,
            length: u32_at(bytes, 8)?, sequence: u64_at(bytes, 16)?, hwnd: u64_at(bytes, 24)? };
        header.validate()?;
        Ok(header)
    }
    /// Length screening runs before payload allocation. # C: O(1)
    pub fn validate(self) -> Result<(), Error> {
        let n = self.length as usize;
        if n > MAX_PAYLOAD || self.sequence == 0 { return Err(Error::Length); }
        if (self.opcode == Opcode::Monitors) != (self.hwnd == 0) { return Err(Error::Payload); }
        let valid = match self.opcode {
            Opcode::Create => n == 32,
            Opcode::Destroy | Opcode::Close => n == 0,
            Opcode::Visibility | Opcode::Ack | Opcode::Focus => n == 4,
            Opcode::Geometry | Opcode::Configure | Opcode::Key | Opcode::Pointer | Opcode::Position => n == 16,
            Opcode::Title | Opcode::Text => n <= MAX_TITLE,
            Opcode::Frame => n >= 16,
            Opcode::Caret => n >= caret::HEADER_BYTES && n <= caret::HEADER_BYTES + caret::MAX_MASK_BYTES,
            Opcode::Monitors => n >= 4 && n <= 4 + MAX_MONITORS * 32 && (n - 4) % 32 == 0,
        };
        if valid { Ok(()) } else { Err(Error::Length) }
    }
    /// # C: O(1)
    pub fn encode(self) -> Result<[u8; HEADER_LEN], Error> {
        self.validate()?;
        let mut out = [0; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes()); out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[6..8].copy_from_slice(&(self.opcode as u16).to_le_bytes()); out[8..12].copy_from_slice(&self.length.to_le_bytes());
        out[16..24].copy_from_slice(&self.sequence.to_le_bytes()); out[24..32].copy_from_slice(&self.hwnd.to_le_bytes());
        Ok(out)
    }
}

impl Rect {
    /// Positive monitor/pixel rectangle. # C: O(1)
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let r = Self::decode_window(bytes)?; r.validate()?; Ok(r)
    }
    /// Window extents may be zero before layout; signed exclusive ends cannot wrap. # C: O(1)
    pub fn decode_window(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 16 { return Err(Error::Length); }
        let r = Self { x: u32_at(bytes, 0)? as i32, y: u32_at(bytes, 4)? as i32,
            width: u32_at(bytes, 8)?, height: u32_at(bytes, 12)? };
        r.validate_window()?; Ok(r)
    }
    /// Monitor workareas and pixel buffers require positive extents. # C: O(1)
    pub fn validate(self) -> Result<(), Error> {
        if self.width == 0 || self.height == 0 { return Err(Error::Payload); }
        self.validate_window()
    }
    /// Zero-sized HWNDs retain their real geometry without invented backing dimensions. # C: O(1)
    pub fn validate_window(self) -> Result<(), Error> {
        if self.width > MAX_DIMENSION || self.height > MAX_DIMENSION { return Err(Error::Payload); }
        self.x.checked_add(self.width as i32).ok_or(Error::Overflow)?;
        self.y.checked_add(self.height as i32).ok_or(Error::Overflow)?; Ok(())
    }
    /// Positive monitor/pixel rectangle. # C: O(1)
    pub fn encode(self) -> Result<[u8; 16], Error> {
        self.validate()?; self.encode_window()
    }
    /// Window geometry, including logical 0x0 child windows. # C: O(1)
    pub fn encode_window(self) -> Result<[u8; 16], Error> {
        self.validate_window()?; let mut out = [0; 16];
        for (i, value) in [self.x as u32, self.y as u32, self.width, self.height].iter().enumerate() { out[i*4..i*4+4].copy_from_slice(&value.to_le_bytes()); }
        Ok(out)
    }
}

/// Validate an owned pixel extent without multiplication wrap or trailing bytes. # C: O(1)
pub fn pixel_len(width: u32, height: u32, stride: u32, format: u32) -> Result<usize, Error> {
    Rect { x: 0, y: 0, width, height }.validate()?;
    if format != PIXEL_BGRA8888 || stride % 4 != 0 || stride < width.checked_mul(4).ok_or(Error::Overflow)? { return Err(Error::Payload); }
    let n = (stride as usize).checked_mul(height as usize).ok_or(Error::Overflow)?;
    if n > MAX_PAYLOAD - 16 { return Err(Error::Length); } Ok(n)
}

impl Record {
    /// # C: O(payload length)
    pub fn new(opcode: Opcode, sequence: u64, hwnd: u64, payload: Vec<u8>) -> Result<Self, Error> {
        let length = u32::try_from(payload.len()).map_err(|_| Error::Length)?;
        let record = Self { header: Header { opcode, length, sequence, hwnd }, payload };
        record.validate()?; Ok(record)
    }
    /// # C: O(payload length)
    pub fn validate(&self) -> Result<(), Error> {
        self.header.validate()?;
        let p = &self.payload;
        if p.len() != self.header.length as usize { return Err(Error::Length); }
        match self.header.opcode {
            Opcode::Create | Opcode::Geometry | Opcode::Configure => { Rect::decode_window(&p[..16])?; }
            Opcode::Visibility | Opcode::Focus => { if u32_at(p, 0)? > 1 { return Err(Error::Payload); } }
            Opcode::Position => {
                let flags = u32_at(p, 8)?;
                if flags & !(POSITION_ORDER | POSITION_ACTIVATE) != 0 || u32_at(p, 12)? != 0
                    || (flags & POSITION_ORDER == 0 && u64_at(p, 0)? != 0) { return Err(Error::Payload); }
            }
            Opcode::Key => { if u32_at(p, 8)? > 1 { return Err(Error::Payload); } }
            Opcode::Title | Opcode::Text => { if p.contains(&0) || core::str::from_utf8(p).is_err() { return Err(Error::Payload); } }
            Opcode::Frame => {
                let n = pixel_len(u32_at(p, 0)?, u32_at(p, 4)?, u32_at(p, 8)?, u32_at(p, 12)?)?;
                if p.len() != 16 + n { return Err(Error::Length); }
            }
            Opcode::Monitors => { self.monitors()?; }
            Opcode::Caret => caret::validate_payload(p)?,
            _ => {}
        } Ok(())
    }
    /// Empty monitor vector explicitly invalidates the desktop snapshot. # C: O(monitors)
    pub fn monitors(&self) -> Result<Vec<Monitor>, Error> {
        if self.header.opcode != Opcode::Monitors { return Err(Error::Opcode); }
        let count = u32_at(&self.payload, 0)? as usize;
        if count > MAX_MONITORS || self.payload.len() != 4 + count * 32 { return Err(Error::Length); }
        let mut out = Vec::new(); out.try_reserve_exact(count).map_err(|_| Error::Allocation)?;
        for p in self.payload[4..].chunks_exact(32) {
            let monitor = Rect::decode(&p[..16])?; let workarea = Rect::decode(&p[16..])?;
            if workarea.x < monitor.x || workarea.y < monitor.y
                || workarea.x as i64 + workarea.width as i64 > monitor.x as i64 + monitor.width as i64
                || workarea.y as i64 + workarea.height as i64 > monitor.y as i64 + monitor.height as i64 { return Err(Error::Payload); }
            out.push(Monitor { monitor, workarea });
        } Ok(out)
    }
    /// # C: O(payload length)
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?; let mut out = Vec::new();
        out.try_reserve_exact(HEADER_LEN + self.payload.len()).map_err(|_| Error::Allocation)?;
        out.extend_from_slice(&self.header.encode()?); out.extend_from_slice(&self.payload); Ok(out)
    }
}

#[cfg(test)]
#[path = "nt_compositor/tests/focus.rs"]
mod focus_tests;

#[cfg(test)]
#[path = "nt_compositor/tests/position.rs"]
mod position_tests;
