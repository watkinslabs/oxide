//! Canonical system colour roles and their protected solid brushes.
use super::*;

/// Every `COLOR_*` role, in index order 0..=30; the discriminant is the index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SystemColor {
    Scrollbar = 0, Background = 1, ActiveCaption = 2, InactiveCaption = 3, Menu = 4, Window = 5, WindowFrame = 6,
    MenuText = 7, WindowText = 8, CaptionText = 9, ActiveBorder = 10, InactiveBorder = 11, AppWorkspace = 12,
    Highlight = 13, HighlightText = 14, Face = 15, ButtonShadow = 16, GrayText = 17, ButtonText = 18,
    InactiveCaptionText = 19, ButtonHighlight = 20, DarkShadow = 21, Light = 22, InfoText = 23, InfoBackground = 24,
    AlternateFace = 25, HotLight = 26, GradientActiveCaption = 27, GradientInactiveCaption = 28, MenuHilight = 29, MenuBar = 30,
}

pub const SYSTEM_COLOR_COUNT: usize = 31;

const ROLES: [SystemColor; SYSTEM_COLOR_COUNT] = [
    SystemColor::Scrollbar, SystemColor::Background, SystemColor::ActiveCaption, SystemColor::InactiveCaption,
    SystemColor::Menu, SystemColor::Window, SystemColor::WindowFrame, SystemColor::MenuText, SystemColor::WindowText,
    SystemColor::CaptionText, SystemColor::ActiveBorder, SystemColor::InactiveBorder, SystemColor::AppWorkspace,
    SystemColor::Highlight, SystemColor::HighlightText, SystemColor::Face, SystemColor::ButtonShadow,
    SystemColor::GrayText, SystemColor::ButtonText, SystemColor::InactiveCaptionText, SystemColor::ButtonHighlight,
    SystemColor::DarkShadow, SystemColor::Light, SystemColor::InfoText, SystemColor::InfoBackground,
    SystemColor::AlternateFace, SystemColor::HotLight, SystemColor::GradientActiveCaption,
    SystemColor::GradientInactiveCaption, SystemColor::MenuHilight, SystemColor::MenuBar,
];

const WHITE: u32 = 0x00ff_ffff;
const BLACK: u32 = 0x0000_0000;
const FACE_GREY: u32 = 0x00d4_d0c8;
const MID_GREY: u32 = 0x0080_8080;
const DARK_GREY: u32 = 0x0040_4040;
const DESKTOP_BLUE: u32 = 0x003a_6ea5;
const TITLE_BLUE: u32 = 0x000a_246a;
const INFO_YELLOW: u32 = 0x00ff_ffe1;
const ALTERNATE_GREY: u32 = 0x00b5_b5b5;
const HOT_BLUE: u32 = 0x0000_00c8;
const GRADIENT_ACTIVE: u32 = 0x00a6_caf0;
const GRADIENT_INACTIVE: u32 = 0x00c0_c0c0;

impl SystemColor {
    /// Decode a `COLOR_*` index; out-of-range indices have no role. # C: O(1)
    pub fn from_index(index: u32) -> Option<Self> {
        ROLES.get(index as usize).copied()
    }
    /// Initial canonical XRGB palette; no COLORREF conversion at owner boundary. # C: O(1)
    pub const fn color(self) -> u32 {
        match self {
            Self::Window | Self::CaptionText | Self::HighlightText | Self::ButtonHighlight => WHITE,
            Self::WindowFrame | Self::MenuText | Self::WindowText | Self::ButtonText | Self::InfoText => BLACK,
            Self::Scrollbar | Self::Menu | Self::ActiveBorder | Self::InactiveBorder | Self::Face
                | Self::InactiveCaptionText | Self::Light | Self::MenuBar => FACE_GREY,
            Self::InactiveCaption | Self::AppWorkspace | Self::ButtonShadow | Self::GrayText => MID_GREY,
            Self::DarkShadow => DARK_GREY,
            Self::Background => DESKTOP_BLUE,
            Self::ActiveCaption | Self::Highlight | Self::MenuHilight => TITLE_BLUE,
            Self::InfoBackground => INFO_YELLOW,
            Self::AlternateFace => ALTERNATE_GREY,
            Self::HotLight => HOT_BLUE,
            Self::GradientActiveCaption => GRADIENT_ACTIVE,
            Self::GradientInactiveCaption => GRADIENT_INACTIVE,
        }
    }
    const fn slot(self) -> usize { self as usize }
}

#[derive(Default)]
pub struct SystemBrushes { handles: [Option<u32>; SYSTEM_COLOR_COUNT], values: [u32; SYSTEM_COLOR_COUNT] }

impl GdiManager {
    /// Allocate at most one canonical solid brush for each represented role. # C: O(brushes)
    pub fn system_brush(&mut self, role: SystemColor) -> Result<u32, GdiError> {
        self.system_brush_value(role, role.color())
    }
    /// The cached brush is reused only while it still carries the role's
    /// current colour, so a changed system colour produces a new brush.
    /// # C: O(objects)
    pub fn system_brush_value(&mut self, role: SystemColor, value: u32) -> Result<u32, GdiError> {
        if let Some(handle) = self.system_brushes.handles[role.slot()].filter(|_| self.system_brushes.values[role.slot()] == value) {
            return if self.contains_object(handle) { Ok(handle) } else { Err(GdiError::NoSuchObject) };
        }
        let handle = self.create_solid_brush(value)?;
        self.system_brushes.handles[role.slot()] = Some(handle);
        self.system_brushes.values[role.slot()] = value;
        Ok(handle)
    }
    /// Both generic and brush-specific deletion check protection before mutation. # C: O(1)
    pub fn is_system_brush(&self, handle: u32) -> bool {
        self.system_brushes.handles.iter().any(|candidate| *candidate == Some(handle))
    }
}

#[cfg(test)]
#[path = "tests/system_brush.rs"]
mod tests;

/// The session's system-colour values. Every role starts at its documented
/// default and a set replaces one role's value for every later query.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SystemColorTable { values: [u32; SYSTEM_COLOR_COUNT], overridden: [bool; SYSTEM_COLOR_COUNT] }

impl SystemColorTable {
    /// # C: O(1)
    pub const fn new() -> Self { Self { values: [0; SYSTEM_COLOR_COUNT], overridden: [false; SYSTEM_COLOR_COUNT] } }
    /// # C: O(1)
    pub fn value(&self, role: SystemColor) -> u32 {
        let slot = role as usize;
        if self.overridden[slot] { self.values[slot] } else { role.color() }
    }
    /// Store one role's value and report the value it replaced. # C: O(1)
    pub fn set(&mut self, role: SystemColor, value: u32) -> u32 {
        let slot = role as usize;
        let previous = self.value(role);
        self.values[slot] = value; self.overridden[slot] = true;
        previous
    }
    /// Whether any role still carries its default. # C: O(N_roles)
    pub fn is_default(&self) -> bool { self.overridden.iter().all(|flag| !flag) }
}

impl Default for SystemColorTable { fn default() -> Self { Self::new() } }

#[cfg(test)]
#[path = "tests/system_color_table.rs"]
mod system_color_table_tests;
