//! Default WM_ERASEBKGND: fill the DC's clip box with the class background brush.
pub(crate) const WM_ERASEBKGND: u32 = 0x0014;
pub(crate) const WM_ICONERASEBKGND: u32 = 0x0027;
/// hbrBackground values up to this are a system colour index plus one.
pub(crate) const COLOR_MENUBAR: u64 = 30;
pub(crate) const CS_PARENTDC: u32 = 0x0080;
pub(crate) const PATCOPY: u32 = 0x00f0_0021;

/// # C: O(1)
pub(crate) const fn is_erase_message(message: u32) -> bool { matches!(message, WM_ERASEBKGND | WM_ICONERASEBKGND) }

/// A zero background means the class does not erase (the message answers 0).
/// A value no larger than COLOR_MENUBAR+1 names a system colour brush; anything
/// else is the brush handle itself. # C: O(1)
pub(crate) fn brush_for(background: u64, system: impl FnOnce(u32) -> Option<u32>) -> Option<u32> {
    if background == 0 { return None; }
    if background <= COLOR_MENUBAR + 1 { return system((background - 1) as u32); }
    u32::try_from(background).ok()
}

/// A parent-DC class fills its own client rectangle; every other class fills
/// the DC's clip box. # C: O(1)
pub(crate) const fn fills_client_rect(class_style: u32) -> bool { class_style & CS_PARENTDC != 0 }

#[cfg(target_os = "oxide-kernel")]
#[path = "erase_background/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path = "erase_background/tests.rs"]
mod tests;
