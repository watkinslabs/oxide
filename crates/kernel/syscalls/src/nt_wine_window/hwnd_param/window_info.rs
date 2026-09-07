//! `WINDOWINFO` encoding. Both rectangles are screen-relative, and the two
//! border widths are derived from them rather than from any frame metric, so
//! they describe the frame the window actually has.

use super::params::Rect;

pub(crate) const WINDOWINFO_BYTES: usize = 60;
/// `dwWindowStatus` when the window owns the active caption.
pub(crate) const WS_ACTIVECAPTION: u32 = 0x0001;
/// The version every window reports as its creator.
pub(crate) const CREATOR_VERSION: u16 = 0x0400;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct WindowInfo {
    pub window: Rect,
    pub client: Rect,
    pub style: u32,
    pub ex_style: u32,
    pub active: bool,
    pub class_atom: u16,
}

impl WindowInfo {
    /// # C: O(1)
    pub(crate) fn encode(self) -> [u8; WINDOWINFO_BYTES] {
        let mut out = [0u8; WINDOWINFO_BYTES];
        out[0..4].copy_from_slice(&(WINDOWINFO_BYTES as u32).to_le_bytes());
        out[4..20].copy_from_slice(&self.window.encode());
        out[20..36].copy_from_slice(&self.client.encode());
        out[36..40].copy_from_slice(&self.style.to_le_bytes());
        out[40..44].copy_from_slice(&self.ex_style.to_le_bytes());
        out[44..48].copy_from_slice(&if self.active { WS_ACTIVECAPTION } else { 0 }.to_le_bytes());
        out[48..52].copy_from_slice(&self.client.left.saturating_sub(self.window.left).to_le_bytes());
        out[52..56].copy_from_slice(&self.window.bottom.saturating_sub(self.client.bottom).to_le_bytes());
        out[56..58].copy_from_slice(&self.class_atom.to_le_bytes());
        out[58..60].copy_from_slice(&CREATOR_VERSION.to_le_bytes());
        out
    }
}

#[cfg(test)]
#[path = "tests/window_info.rs"]
mod tests;
