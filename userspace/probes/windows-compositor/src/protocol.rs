use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

use crate::{MonitorSnapshot, Rect};
use syscall::nt_compositor::{self as wire, Opcode, Record};

pub const MAX_TITLE_UNITS: usize = 4096;
pub const MAX_PIXELS: usize = 16 * 1024 * 1024;

/// One update of a window's surface: the extent the surface has, the damaged
/// sub-rectangle of it, and only that sub-rectangle's pixels, `stride` of them
/// per row. The surface itself is retained by the backend across frames, so a
/// re-expose repaints from its own copy rather than from a resend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame { pub width: u32, pub height: u32, pub stride: u32, pub pixels: Vec<u32>, pub damage: Rect }

impl Frame {
    pub fn new(width: u32, height: u32, stride: u32, pixels: Vec<u32>, damage: Rect) -> Result<Self, TransportError> {
        if width == 0 || height == 0 || !damage.is_inside(width, height) { return Err(TransportError::InvalidFrame); }
        let rows = usize::try_from(damage.bottom - damage.top).map_err(|_| TransportError::InvalidFrame)?;
        let row = u32::try_from(damage.right - damage.left).map_err(|_| TransportError::InvalidFrame)?;
        let count = usize::try_from(stride).ok().and_then(|s| s.checked_mul(rows)).ok_or(TransportError::InvalidFrame)?;
        if stride < row || count > MAX_PIXELS || pixels.len() != count { return Err(TransportError::InvalidFrame); }
        Ok(Self { width, height, stride, pixels, damage })
    }
    /// Pixels of one carried row of the damage rectangle. # C: O(1)
    pub fn row(&self, index: usize) -> Option<&[u32]> {
        let row = (self.damage.right - self.damage.left) as usize;
        let start = index.checked_mul(self.stride as usize)?;
        self.pixels.get(start..start.checked_add(row)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeCommand {
    Create { hwnd: u32, title: Vec<u16>, rect: Rect, parent: u64, style: u32, ex_style: u32 },
    Show { hwnd: u32 },
    Hide { hwnd: u32 },
    SetTitle { hwnd: u32, title: Vec<u16> },
    Configure { hwnd: u32, rect: Rect },
    Frame { hwnd: u32, frame: Frame },
    Position { hwnd: u32, insertion: Option<u64>, activate: bool },
    Caret { hwnd: u32, snapshot: wire::caret::Snapshot },
    Destroy { hwnd: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeEvent {
    Ack { sequence: u64, hwnd: u64, status: u32 },
    WorkArea(MonitorSnapshot),
    Configure { hwnd: u32, rect: Rect },
    /// One rectangle of a window whose pixels the display has lost and cannot
    /// restore from the surface this backend retains, in the window's own
    /// coordinates.
    Damage { hwnd: u32, rect: Rect },
    Input(InputEvent),
    Close { hwnd: u32 },
    Destroyed { hwnd: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputEvent {
    Key { hwnd: u32, press: bool, virtual_key: u32, scan_code: u8, modifiers: u32 },
    Text { hwnd: u32, utf8: Vec<u8> },
    /// X forms, before translation: an X button number and an X modifier
    /// state, neither of which is a Win32 value.
    Button { hwnd: u32, press: bool, button: u8, x: i16, y: i16, state: u16 },
    Motion { hwnd: u32, x: i16, y: i16, state: u16 },
    /// Translated form: a Win32 button mask and both wheel axes.
    Pointer { hwnd: u32, x: i16, y: i16, buttons: u32, wheel: i32, hwheel: i32 },
    Focus { hwnd: u32, focused: bool },
}

pub trait NativeTransport {
    fn recv(&mut self) -> Result<Option<Inbound>, TransportError>;
    fn send(&mut self, event: BridgeEvent) -> Result<(), TransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inbound { pub sequence: u64, pub hwnd: u64, pub command: BridgeCommand }

#[derive(Debug)]
pub enum TransportError { InvalidFrame, InvalidTitle, Disconnected, Io(io::Error), Unsupported }

pub fn validate_title(title: &[u16]) -> Result<(), TransportError> {
    if title.len() > MAX_TITLE_UNITS || title.contains(&0) { Err(TransportError::InvalidTitle) } else { Ok(()) }
}

/// The property type a window name is published under, and the bytes that go
/// with it. A name every unit of which is Latin-1 is published as the
/// single-byte string type the window-name convention names; anything else has
/// to travel as UTF-8, which is the type the extended name always uses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TitleEncoding { Latin1(Vec<u8>), Utf8(Vec<u8>) }

/// Encode one window name for the conventional `WM_NAME` property. The
/// extended `_NET_WM_NAME` property is always UTF-8 and is encoded by the
/// caller from the same string. # C: O(N_units)
pub fn encode_wm_name(title: &[u16]) -> TitleEncoding {
    let text = String::from_utf16_lossy(title);
    if text.chars().all(|c| (c as u32) < 0x100) {
        TitleEncoding::Latin1(text.chars().map(|c| c as u8).collect())
    } else {
        TitleEncoding::Utf8(text.into_bytes())
    }
}

pub struct StreamTransport { stream: UnixStream, rx: Vec<u8>, next: u64 }

impl StreamTransport {
    pub fn from_fd0() -> Result<Self, TransportError> { Self::from_fd(0) }
    pub fn from_fd(fd: RawFd) -> Result<Self, TransportError> { let stream = unsafe { UnixStream::from_raw_fd(fd) }; stream.set_nonblocking(true).map_err(TransportError::Io)?; Ok(Self { stream, rx: Vec::new(), next: 1 }) }
    pub fn from_stream(stream: UnixStream) -> Result<Self, TransportError> { stream.set_nonblocking(true).map_err(TransportError::Io)?; Ok(Self { stream, rx: Vec::new(), next: 1 }) }
    fn read_record(&mut self) -> Result<Option<Record>, TransportError> {
        let mut scratch = [0u8; 8192];
        loop { match self.stream.read(&mut scratch) { Ok(0) => return Err(TransportError::Disconnected), Ok(n) => self.rx.extend_from_slice(&scratch[..n]), Err(e) if e.kind() == io::ErrorKind::WouldBlock => break, Err(e) => return Err(TransportError::Io(e)) } }
        if self.rx.len() < wire::HEADER_LEN { return Ok(None); }
        let header = wire::Header::decode(&self.rx[..wire::HEADER_LEN]).map_err(|_| TransportError::Unsupported)?;
        if header.opcode.from_backend() { return Err(TransportError::Unsupported); }
        let total = wire::HEADER_LEN.checked_add(header.length as usize).ok_or(TransportError::Unsupported)?;
        if self.rx.len() < total { return Ok(None); }
        let bytes: Vec<u8> = self.rx.drain(..total).collect();
        let record = Record { header, payload: bytes[wire::HEADER_LEN..].to_vec() }; record.validate().map_err(|_| TransportError::Unsupported)?; Ok(Some(record))
    }
}

/// The bridge socket, so a caller can block on it rather than ask a
/// non-blocking socket for a record that has not arrived. Bytes already
/// buffered here do not make it readable, so a caller drains `recv` to
/// `None` before waiting on it.
impl AsRawFd for StreamTransport { fn as_raw_fd(&self) -> RawFd { self.stream.as_raw_fd() } }

impl NativeTransport for StreamTransport {
    fn recv(&mut self) -> Result<Option<Inbound>, TransportError> {
        let Some(record) = self.read_record()? else { return Ok(None); };
        let command = decode_command(record.header.opcode, record.header.hwnd, &record.payload)?;
        Ok(Some(Inbound { sequence: record.header.sequence, hwnd: record.header.hwnd, command }))
    }
    fn send(&mut self, event: BridgeEvent) -> Result<(), TransportError> {
        let (opcode, hwnd, payload, sequence) = encode_event(&event, self.next)?;
        if sequence == self.next { self.next = self.next.checked_add(1).ok_or(TransportError::Unsupported)?; }
        let bytes = Record::new(opcode, sequence, hwnd, payload).map_err(|_| TransportError::Unsupported)?.encode().map_err(|_| TransportError::Unsupported)?;
        self.stream.write_all(&bytes).map_err(TransportError::Io)
    }
}

fn rect_from_wire(p: &[u8]) -> Result<Rect, TransportError> { let r = wire::Rect::decode(p).map_err(|_| TransportError::Unsupported)?; Ok(Rect { left: r.x, top: r.y, right: r.x.checked_add(r.width as i32).ok_or(TransportError::InvalidFrame)?, bottom: r.y.checked_add(r.height as i32).ok_or(TransportError::InvalidFrame)? }) }
fn window_rect_from_wire(p: &[u8]) -> Result<Rect, TransportError> { if p.len() != 16 { return Err(TransportError::Unsupported); } let x = wire::u32_at(p, 0).map_err(|_| TransportError::Unsupported)? as i32; let y = wire::u32_at(p, 4).map_err(|_| TransportError::Unsupported)? as i32; let width = wire::u32_at(p, 8).map_err(|_| TransportError::Unsupported)?; let height = wire::u32_at(p, 12).map_err(|_| TransportError::Unsupported)?; if width > wire::MAX_DIMENSION || height > wire::MAX_DIMENSION { return Err(TransportError::InvalidFrame); } Ok(Rect { left: x, top: y, right: x.checked_add(width as i32).ok_or(TransportError::InvalidFrame)?, bottom: y.checked_add(height as i32).ok_or(TransportError::InvalidFrame)? }) }
fn decode_command(opcode: Opcode, hwnd: u64, p: &[u8]) -> Result<BridgeCommand, TransportError> {
    let id = u32::try_from(hwnd).map_err(|_| TransportError::Unsupported)?;
    Ok(match opcode {
        Opcode::Create => BridgeCommand::Create { hwnd: id, title: Vec::new(), rect: window_rect_from_wire(&p[..16])?, parent: wire::u64_at(p, 16).map_err(|_| TransportError::Unsupported)?, style: wire::u32_at(p, 24).map_err(|_| TransportError::Unsupported)?, ex_style: wire::u32_at(p, 28).map_err(|_| TransportError::Unsupported)? },
        Opcode::Destroy => BridgeCommand::Destroy { hwnd: id },
        Opcode::Caret => BridgeCommand::Caret { hwnd: id, snapshot: wire::caret::Snapshot::decode(p).map_err(|_| TransportError::InvalidFrame)? },
        Opcode::Visibility => if wire::u32_at(p, 0).map_err(|_| TransportError::Unsupported)? == 1 { BridgeCommand::Show { hwnd: id } } else { BridgeCommand::Hide { hwnd: id } },
        Opcode::Title => { let text = std::str::from_utf8(p).map_err(|_| TransportError::InvalidTitle)?; BridgeCommand::SetTitle { hwnd: id, title: text.encode_utf16().collect() } },
        Opcode::Geometry | Opcode::Configure => BridgeCommand::Configure { hwnd: id, rect: window_rect_from_wire(p)? },
        Opcode::Position => { let after = wire::u64_at(p, 0).map_err(|_| TransportError::Unsupported)?; let flags = wire::u32_at(p, 8).map_err(|_| TransportError::Unsupported)?; if flags & ! (wire::POSITION_ORDER | wire::POSITION_ACTIVATE) != 0 || wire::u32_at(p, 12).map_err(|_| TransportError::Unsupported)? != 0 || flags & wire::POSITION_ORDER == 0 && after != 0 || id == 0 { return Err(TransportError::Unsupported); } BridgeCommand::Position { hwnd: id, insertion: (flags & wire::POSITION_ORDER != 0).then_some(after), activate: flags & wire::POSITION_ACTIVATE != 0 } },
        // The damage the sender measured travels with the surface. Repainting
        // the whole window instead costs one server request per tile of it on
        // every paint, which is what a caret blink or a typed character used
        // to pay.
        Opcode::Frame => { let width = wire::u32_at(p, 0).map_err(|_| TransportError::Unsupported)?; let height = wire::u32_at(p, 4).map_err(|_| TransportError::Unsupported)?; let stride = wire::u32_at(p, 8).map_err(|_| TransportError::Unsupported)?; let format = wire::u32_at(p, 12).map_err(|_| TransportError::Unsupported)?; if p.len() < wire::FRAME_HEADER_BYTES { return Err(TransportError::InvalidFrame); } let damage = wire::Damage::decode(&p[16..wire::FRAME_HEADER_BYTES]).map_err(|_| TransportError::InvalidFrame)?; let bytes = &p[wire::FRAME_HEADER_BYTES..]; if wire::frame_pixel_len(width, height, stride, format, damage).map_err(|_| TransportError::InvalidFrame)? != bytes.len() || bytes.len() % 4 != 0 { return Err(TransportError::InvalidFrame); } let pixels = bytes.chunks_exact(4).map(|v| u32::from_le_bytes(v.try_into().unwrap())).collect(); BridgeCommand::Frame { hwnd: id, frame: Frame::new(width, height, stride / 4, pixels, Rect { left: damage.left, top: damage.top, right: damage.right, bottom: damage.bottom }).map_err(|_| TransportError::InvalidFrame)? } },
        _ => return Err(TransportError::Unsupported),
    })
}

pub(crate) fn encode_event(event: &BridgeEvent, next: u64) -> Result<(Opcode, u64, Vec<u8>, u64), TransportError> {
    match event {
        BridgeEvent::Ack { sequence, hwnd, status } => Ok((Opcode::Ack, *hwnd, status.to_le_bytes().to_vec(), *sequence)),
        BridgeEvent::WorkArea(snapshot) => { let mut p = Vec::with_capacity(36); p.extend_from_slice(&1u32.to_le_bytes()); for r in [snapshot.monitor, snapshot.work_area] { let x = r.left; let y = r.top; let w = (r.right - r.left) as u32; let h = (r.bottom - r.top) as u32; p.extend_from_slice(&(x as u32).to_le_bytes()); p.extend_from_slice(&(y as u32).to_le_bytes()); p.extend_from_slice(&w.to_le_bytes()); p.extend_from_slice(&h.to_le_bytes()); } Ok((Opcode::Monitors, 0, p, next)) }
        BridgeEvent::Configure { hwnd, rect } => Ok((Opcode::Configure, *hwnd as u64, wire_rect(*rect)?, next)),
        BridgeEvent::Damage { hwnd, rect } => Ok((Opcode::Damage, *hwnd as u64, wire_rect(*rect)?, next)),
        BridgeEvent::Close { hwnd } => Ok((Opcode::Close, *hwnd as u64, Vec::new(), next)),
        BridgeEvent::Destroyed { hwnd } => Ok((Opcode::Ack, *hwnd as u64, 0u32.to_le_bytes().to_vec(), next)),
        BridgeEvent::Input(InputEvent::Key { hwnd, press, virtual_key, scan_code, modifiers }) => { if *virtual_key == 0 || *virtual_key > 0xff || *modifiers & !(crate::keyboard::KEY_EXTENDED | crate::keyboard::KEY_ALT | crate::keyboard::KEY_PREVIOUS) != 0 { return Err(TransportError::Unsupported); } let mut p = Vec::new(); p.extend_from_slice(&virtual_key.to_le_bytes()); p.extend_from_slice(&(*scan_code as u32).to_le_bytes()); p.extend_from_slice(&(*press as u32).to_le_bytes()); p.extend_from_slice(&modifiers.to_le_bytes()); Ok((Opcode::Key, *hwnd as u64, p, next)) }
        BridgeEvent::Input(InputEvent::Text { hwnd, utf8 }) => Ok((Opcode::Text, *hwnd as u64, utf8.clone(), next)),
        // The X forms never reach the wire: an X modifier state read as a
        // Win32 button mask reports a click that did not happen and loses the
        // one that did, so the translation is not optional.
        BridgeEvent::Input(InputEvent::Button { .. }) | BridgeEvent::Input(InputEvent::Motion { .. }) => Err(TransportError::Unsupported),
        BridgeEvent::Input(InputEvent::Pointer { hwnd, x, y, buttons, wheel, hwheel }) => {
            if buttons & !crate::pointer::MK_ALL != 0 || i16::try_from(*wheel).is_err() || i16::try_from(*hwheel).is_err() { return Err(TransportError::Unsupported); }
            let mut p = Vec::new();
            p.extend_from_slice(&(*x as i32 as u32).to_le_bytes()); p.extend_from_slice(&(*y as i32 as u32).to_le_bytes());
            p.extend_from_slice(&buttons.to_le_bytes()); p.extend_from_slice(&wheel.to_le_bytes()); p.extend_from_slice(&hwheel.to_le_bytes());
            Ok((Opcode::Pointer, *hwnd as u64, p, next))
        }
        BridgeEvent::Input(InputEvent::Focus { hwnd, focused }) => { if *hwnd == 0 { return Err(TransportError::Unsupported); } Ok((Opcode::Focus, *hwnd as u64, (*focused as u32).to_le_bytes().to_vec(), next)) }
    }
}

fn wire_rect(r: Rect) -> Result<Vec<u8>, TransportError> { let w = u32::try_from(r.right.checked_sub(r.left).ok_or(TransportError::InvalidFrame)?).map_err(|_| TransportError::InvalidFrame)?; let h = u32::try_from(r.bottom.checked_sub(r.top).ok_or(TransportError::InvalidFrame)?).map_err(|_| TransportError::InvalidFrame)?; wire::Rect { x: r.left, y: r.top, width: w, height: h }.encode().map(|v| v.to_vec()).map_err(|_| TransportError::InvalidFrame) }

#[cfg(test)]
#[path = "tests/frame_damage.rs"]
mod tests;
