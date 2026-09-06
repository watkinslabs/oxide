//! System-color query ingress; palette and protected brush lifetime stay canonical, 31ge§6.
use ipc::win32_gdi::SystemColor;
pub(crate) const CALL_ONE_PARAM: u64 = 0x133d;
pub(crate) const GET_SYS_COLOR: u32 = 6;
pub(crate) const GET_SYS_COLOR_BRUSH: u32 = 7;

/// No shadow palette/cache; owner color becomes COLORREF only at this ABI boundary.
/// # C: O(1) plus canonical protected-brush lookup/publication
pub(crate) fn route<E>(ordinal: u64, args: &[u64], brush: impl FnOnce(SystemColor) -> Result<u32, E>) -> Option<u64> {
    if ordinal != CALL_ONE_PARAM || args.len() < 2 { return None; }
    let selector = args[1] as u32;
    if selector != GET_SYS_COLOR && selector != GET_SYS_COLOR_BRUSH { return None; }
    let Some(role) = SystemColor::from_index(args[0] as u32) else { return Some(0); };
    Some(if selector == GET_SYS_COLOR {
        let color = role.color();
        (((color & 0xff) << 16) | (color & 0xff00) | ((color >> 16) & 0xff)) as u64
    } else { brush(role).map_or(0, u64::from) })
}

#[cfg(test)]
#[path = "tests/system_color_raw.rs"]
mod tests;
