use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

use crate::{MonitorSnapshot, Rect};
use syscall::nt_compositor::{self as wire, Opcode, Record};

pub const MAX_TITLE_UNITS: usize = 4096;
pub const MAX_PIXELS: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame { pub width: u32, pub height: u32, pub stride: u32, pub pixels: Vec<u32>, pub damage: Rect }

impl Frame {
    pub fn new(width: u32, height: u32, stride: u32, pixels: Vec<u32>, damage: Rect) -> Result<Self, TransportError> {
        let count = usize::try_from(stride).ok().and_then(|s| usize::try_from(height).ok().and_then(|h| s.checked_mul(h))).ok_or(TransportError::InvalidFrame)?;
        if width == 0 || height == 0 || stride < width || count > MAX_PIXELS || pixels.len() != count || !damage.is_inside(width, height) {
            return Err(TransportError::InvalidFrame);
        }
        Ok(Self { width, height, stride, pixels, damage })
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
    Input(InputEvent),
    Close { hwnd: u32 },
    Destroyed { hwnd: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputEvent {
    Key { hwnd: u32, press: bool, virtual_key: u32, scan_code: u8, modifiers: u32 },
    Text { hwnd: u32, utf8: Vec<u8> },
    Button { hwnd: u32, press: bool, button: u8, x: i16, y: i16, state: u16 },
    Motion { hwnd: u32, x: i16, y: i16, state: u16 },
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
        Opcode::Frame => { let width = wire::u32_at(p, 0).map_err(|_| TransportError::Unsupported)?; let height = wire::u32_at(p, 4).map_err(|_| TransportError::Unsupported)?; let stride = wire::u32_at(p, 8).map_err(|_| TransportError::Unsupported)?; let format = wire::u32_at(p, 12).map_err(|_| TransportError::Unsupported)?; let bytes = &p[16..]; if wire::pixel_len(width, height, stride, format).map_err(|_| TransportError::InvalidFrame)? != bytes.len() || bytes.len() % 4 != 0 { return Err(TransportError::InvalidFrame); } let pixels = bytes.chunks_exact(4).map(|v| u32::from_le_bytes(v.try_into().unwrap())).collect(); BridgeCommand::Frame { hwnd: id, frame: Frame::new(width, height, stride / 4, pixels, Rect { left: 0, top: 0, right: width as i32, bottom: height as i32 }).map_err(|_| TransportError::InvalidFrame)? } },
        _ => return Err(TransportError::Unsupported),
    })
}

pub(crate) fn encode_event(event: &BridgeEvent, next: u64) -> Result<(Opcode, u64, Vec<u8>, u64), TransportError> {
    match event {
        BridgeEvent::Ack { sequence, hwnd, status } => Ok((Opcode::Ack, *hwnd, status.to_le_bytes().to_vec(), *sequence)),
        BridgeEvent::WorkArea(snapshot) => { let mut p = Vec::with_capacity(36); p.extend_from_slice(&1u32.to_le_bytes()); for r in [snapshot.monitor, snapshot.work_area] { let x = r.left; let y = r.top; let w = (r.right - r.left) as u32; let h = (r.bottom - r.top) as u32; p.extend_from_slice(&(x as u32).to_le_bytes()); p.extend_from_slice(&(y as u32).to_le_bytes()); p.extend_from_slice(&w.to_le_bytes()); p.extend_from_slice(&h.to_le_bytes()); } Ok((Opcode::Monitors, 0, p, next)) }
        BridgeEvent::Configure { hwnd, rect } => Ok((Opcode::Configure, *hwnd as u64, wire_rect(*rect)?, next)),
        BridgeEvent::Close { hwnd } => Ok((Opcode::Close, *hwnd as u64, Vec::new(), next)),
        BridgeEvent::Destroyed { hwnd } => Ok((Opcode::Ack, *hwnd as u64, 0u32.to_le_bytes().to_vec(), next)),
        BridgeEvent::Input(InputEvent::Key { hwnd, press, virtual_key, scan_code, modifiers }) => { if *virtual_key == 0 || *virtual_key > 0xff || *modifiers & !(crate::keyboard::KEY_EXTENDED | crate::keyboard::KEY_ALT | crate::keyboard::KEY_PREVIOUS) != 0 { return Err(TransportError::Unsupported); } let mut p = Vec::new(); p.extend_from_slice(&virtual_key.to_le_bytes()); p.extend_from_slice(&(*scan_code as u32).to_le_bytes()); p.extend_from_slice(&(*press as u32).to_le_bytes()); p.extend_from_slice(&modifiers.to_le_bytes()); Ok((Opcode::Key, *hwnd as u64, p, next)) }
        BridgeEvent::Input(InputEvent::Text { hwnd, utf8 }) => Ok((Opcode::Text, *hwnd as u64, utf8.clone(), next)),
        BridgeEvent::Input(InputEvent::Button { hwnd, x, y, state, .. }) | BridgeEvent::Input(InputEvent::Motion { hwnd, x, y, state }) => { let mut p = Vec::new(); p.extend_from_slice(&(*x as i32 as u32).to_le_bytes()); p.extend_from_slice(&(*y as i32 as u32).to_le_bytes()); p.extend_from_slice(&(*state as u32).to_le_bytes()); p.extend_from_slice(&0i32.to_le_bytes()); Ok((Opcode::Pointer, *hwnd as u64, p, next)) }
        BridgeEvent::Input(InputEvent::Focus { hwnd, focused }) => { if *hwnd == 0 { return Err(TransportError::Unsupported); } Ok((Opcode::Focus, *hwnd as u64, (*focused as u32).to_le_bytes().to_vec(), next)) }
    }
}

fn wire_rect(r: Rect) -> Result<Vec<u8>, TransportError> { let w = u32::try_from(r.right.checked_sub(r.left).ok_or(TransportError::InvalidFrame)?).map_err(|_| TransportError::InvalidFrame)?; let h = u32::try_from(r.bottom.checked_sub(r.top).ok_or(TransportError::InvalidFrame)?).map_err(|_| TransportError::InvalidFrame)?; wire::Rect { x: r.left, y: r.top, width: w, height: h }.encode().map(|v| v.to_vec()).map_err(|_| TransportError::InvalidFrame) }
