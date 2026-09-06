use ipc::win32_window::WindowRect;
use syscall::nt_compositor::Rect;

pub(super) const BYTES: usize = 44;
pub(super) const SW_HIDE: u32 = 0;
pub(super) const SW_SHOWNORMAL: u32 = 1;
pub(super) const SW_SHOWNOACTIVATE: u32 = 4;
pub(super) const SW_SHOW: u32 = 5;
pub(super) const SW_SHOWNA: u32 = 8;
pub(super) const SW_RESTORE: u32 = 9;
pub(super) const SW_SHOWDEFAULT: u32 = 10;
#[cfg(test)]
pub(super) const WS_CHILD: u32 = 0x4000_0000;
pub(super) const WS_MINIMIZE: u32 = 0x2000_0000;
pub(super) const WS_MAXIMIZE: u32 = 0x0100_0000;
#[cfg(test)]
pub(super) const WS_EX_TOOLWINDOW: u32 = 0x80;
pub(super) const WPF_SETMINPOSITION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Context { pub rect: WindowRect, pub style: u32, pub ex_style: u32 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Placement { pub flags: u32, pub show: u32, pub min: (i32, i32), pub max: (i32, i32), pub normal: WindowRect }

fn field(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset+4)?.try_into().ok()?))
}

/// Signed RECT differences and transport dimensions must be valid before mutation. # C: O(1)
pub(super) fn valid_rect(rect: WindowRect) -> bool {
    let Some(width) = rect.right.checked_sub(rect.left).and_then(|n| u32::try_from(n).ok()) else { return false; };
    let Some(height) = rect.bottom.checked_sub(rect.top).and_then(|n| u32::try_from(n).ok()) else { return false; };
    Rect { x: rect.left, y: rect.top, width, height }.validate_window().is_ok()
}

impl Placement {
    /// Layout is 44 bytes on both 64-bit architectures; POINT/RECT use signed 32-bit fields. # C: O(1)
    pub(super) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BYTES || field(bytes, 0)? != BYTES as u32 { return None; }
        let normal = WindowRect { left: field(bytes, 28)? as i32, top: field(bytes, 32)? as i32,
            right: field(bytes, 36)? as i32, bottom: field(bytes, 40)? as i32 };
        if !valid_rect(normal) { return None; }
        Some(Self { flags: field(bytes, 4)?, show: field(bytes, 8)?,
            min: (field(bytes, 12)? as i32, field(bytes, 16)? as i32),
            max: (field(bytes, 20)? as i32, field(bytes, 24)? as i32), normal })
    }
    /// # C: O(1)
    pub(super) fn encode(self) -> [u8; BYTES] {
        let fields = [BYTES as u32, self.flags, self.show, self.min.0 as u32, self.min.1 as u32,
            self.max.0 as u32, self.max.1 as u32, self.normal.left as u32, self.normal.top as u32,
            self.normal.right as u32, self.normal.bottom as u32];
        let mut bytes = [0; BYTES];
        for (i, value) in fields.iter().enumerate() { bytes[i*4..i*4+4].copy_from_slice(&value.to_le_bytes()); }
        bytes
    }
}
