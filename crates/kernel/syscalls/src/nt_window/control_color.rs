//! Default parent control-color policy and canonical GDI adapter; 31fk§5.
use ipc::win32_gdi::{SystemColor, TextAttribute};

const WM_CTLCOLORMSGBOX: u32 = 0x0132;
const WM_CTLCOLOREDIT: u32 = 0x0133;
const WM_CTLCOLORLISTBOX: u32 = 0x0134;
const WM_CTLCOLORBTN: u32 = 0x0135;
const WM_CTLCOLORDLG: u32 = 0x0136;
const WM_CTLCOLORSTATIC: u32 = 0x0138;

/// Background and brush share one canonical role. Scrollbars need patterned brush work.
/// # C: O(1)
pub(crate) fn role(message: u32) -> Option<SystemColor> {
    match message {
        WM_CTLCOLOREDIT | WM_CTLCOLORLISTBOX => Some(SystemColor::Window),
        WM_CTLCOLORMSGBOX | WM_CTLCOLORBTN | WM_CTLCOLORDLG | WM_CTLCOLORSTATIC => Some(SystemColor::Face),
        _ => None,
    }
}

/// The default procedure ignores DC setter failures and still queries the system brush.
/// # C: O(owner work)
pub(crate) fn apply<E>(message: u32, mut set: impl FnMut(TextAttribute, u32) -> Result<u32, E>,
    brush: impl FnOnce(SystemColor) -> Result<u32, E>) -> Option<u64> {
    let role = role(message)?;
    let _ = set(TextAttribute::Foreground, SystemColor::WindowText.color());
    let _ = set(TextAttribute::Background, role.color());
    Some(brush(role).map_or(0, u64::from))
}

#[cfg(target_os = "oxide-kernel")]
#[path = "control_color/kernel.rs"]
mod kernel;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use kernel::for_current;

#[cfg(test)]
#[path = "control_color/tests.rs"]
mod tests;
