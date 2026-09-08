//! System-color query ingress; palette and protected brush/pen lifetime stay canonical, 31ge§6.
use ipc::win32_gdi::SystemColor;
pub(crate) const CALL_ONE_PARAM: u64 = 0x133d;
pub(crate) const GET_SYS_COLOR: u32 = 6;
pub(crate) const GET_SYS_COLOR_BRUSH: u32 = 7;
pub(crate) const GET_SYS_COLOR_PEN: u32 = 8;

/// What the caller asked the role for. The three codes share one index bound
/// check and one refusal answer, which is what keeps a pen query from
/// answering a colour and an out-of-range index from answering a handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Query { Color, Brush, Pen }

/// # C: O(1)
pub(crate) fn query(selector: u32) -> Option<Query> {
    match selector {
        GET_SYS_COLOR => Some(Query::Color),
        GET_SYS_COLOR_BRUSH => Some(Query::Brush),
        GET_SYS_COLOR_PEN => Some(Query::Pen),
        _ => None,
    }
}

/// Owner XRGB becomes a COLORREF only at this ABI boundary. # C: O(1)
pub(crate) fn colorref(color: u32) -> u64 { (((color & 0xff) << 16) | (color & 0xff00) | ((color >> 16) & 0xff)) as u64 }

/// No shadow palette/cache; the object owners publish the protected identities
/// and the session colour table is the one source of every role's value, so a
/// colour query and a brush or pen query can never disagree.
/// An index no role owns answers zero for every one of the three queries, which
/// is the reference's bound check.
/// # C: O(1) plus canonical protected-object lookup/publication
pub(crate) fn route<E>(ordinal: u64, args: &[u64], color: impl FnOnce(SystemColor) -> u32,
    brush: impl FnOnce(SystemColor) -> Result<u32, E>, pen: impl FnOnce(SystemColor) -> Result<u32, E>) -> Option<u64> {
    if ordinal != CALL_ONE_PARAM || args.len() < 2 { return None; }
    let selected = query(args[1] as u32)?;
    let Some(role) = SystemColor::from_index(args[0] as u32) else { return Some(0); };
    Some(match selected {
        Query::Color => colorref(color(role)),
        Query::Brush => brush(role).map_or(0, u64::from),
        Query::Pen => pen(role).map_or(0, u64::from),
    })
}

#[cfg(test)]
#[path = "tests/system_color_raw.rs"]
mod tests;
