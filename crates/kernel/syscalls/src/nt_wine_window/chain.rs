//! One routing chain for every win32u ordinal. 31d§1, 53§2.
//!
//! Both entries into the ordinal space — the tagged descriptor call and the
//! raw win32u thunk — normalize their arguments into one Windows-order array
//! and then walk this single ordered list of family routers. A family reached
//! by one entry is therefore reached by the other by construction; the two
//! hand-maintained chains this replaces disagreed on twelve families, and
//! every ordinal those families owned was refused on the real path.

/// One family router in the chain. Order is `ORDER`; the binding from family
/// to router is the kernel module's exhaustive match, so a family cannot be
/// bound in one entry and not the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    CaretRaw, HwndCall, MsgFilter, TwoParam, DpiContext, InputContext, QueryWindow, AccelRaw,
    ClipboardRaw, AtomRaw, HookRaw, StationRaw, WindowRaw,
    Scroll, MessageQueue, Timer, UpdateRegion, Caption, SysColors, ScrollBar, ScrollDc, MenuRaw,
    Display, Drag, DrawIcon,
    VisibilityRaw, RegionRaw, DcQueryRaw, PenRaw, SetRectRgnRaw, DcRaw, DcStateRaw, XformRaw,
    DrawRaw, PrintRaw,
    Redraw, SystemColorRaw, NonclientRaw, FontQuery, FontFamily,
    PropertyRaw, DcObject, LongRaw, ClassSet, CursorRaw, CursorIconRaw, InputRaw, KeyboardRaw,
    RawInputRaw, HwndParam,
    GdiRoute, ObjectRaw, BitmapRaw, GdiBitmapRaw, DeviceCaps, BrushRaw, ClipRaw, GdiShape,
    KeyboardQuery, Legacy,
}

#[cfg(test)]
/// Every family that exists. A family absent from `ORDER` is unreachable from
/// both entries, which is the defect this chain exists to make impossible.
pub(crate) const ALL: &[Family] = &[
    Family::CaretRaw, Family::HwndCall, Family::MsgFilter, Family::TwoParam, Family::DpiContext,
    Family::InputContext, Family::QueryWindow, Family::AccelRaw,
    Family::ClipboardRaw, Family::AtomRaw, Family::HookRaw, Family::StationRaw, Family::WindowRaw,
    Family::Scroll, Family::MessageQueue, Family::Timer, Family::UpdateRegion, Family::Caption,
    Family::SysColors, Family::ScrollBar, Family::ScrollDc, Family::MenuRaw, Family::Display,
    Family::Drag, Family::DrawIcon,
    Family::VisibilityRaw, Family::RegionRaw, Family::DcQueryRaw, Family::PenRaw,
    Family::SetRectRgnRaw, Family::DcRaw, Family::DcStateRaw, Family::XformRaw, Family::DrawRaw,
    Family::PrintRaw,
    Family::Redraw, Family::SystemColorRaw, Family::NonclientRaw, Family::FontQuery,
    Family::FontFamily,
    Family::PropertyRaw, Family::DcObject, Family::LongRaw, Family::ClassSet, Family::CursorRaw,
    Family::CursorIconRaw, Family::InputRaw, Family::KeyboardRaw, Family::RawInputRaw,
    Family::HwndParam,
    Family::GdiRoute, Family::ObjectRaw, Family::BitmapRaw, Family::GdiBitmapRaw,
    Family::DeviceCaps, Family::BrushRaw, Family::ClipRaw, Family::GdiShape,
    Family::KeyboardQuery, Family::Legacy,
];

/// Walk order. The first family that claims an ordinal answers it; `Legacy`
/// is last because its admission set overlaps the keyboard-state queries the
/// `KeyboardQuery` family owns.
pub(crate) const ORDER: &[Family] = &[
    Family::CaretRaw, Family::HwndCall, Family::MsgFilter, Family::TwoParam, Family::DpiContext,
    Family::InputContext, Family::QueryWindow, Family::AccelRaw,
    Family::ClipboardRaw, Family::AtomRaw, Family::HookRaw, Family::StationRaw, Family::WindowRaw,
    Family::Scroll, Family::MessageQueue, Family::Timer, Family::UpdateRegion, Family::Caption,
    Family::SysColors, Family::ScrollBar, Family::ScrollDc, Family::MenuRaw, Family::Display,
    Family::Drag, Family::DrawIcon,
    Family::VisibilityRaw, Family::RegionRaw, Family::DcQueryRaw, Family::PenRaw,
    Family::SetRectRgnRaw, Family::DcRaw, Family::DcStateRaw, Family::XformRaw, Family::DrawRaw,
    Family::PrintRaw,
    Family::Redraw, Family::SystemColorRaw, Family::NonclientRaw, Family::FontQuery,
    Family::FontFamily,
    Family::PropertyRaw, Family::DcObject, Family::LongRaw, Family::ClassSet, Family::CursorRaw,
    Family::CursorIconRaw, Family::InputRaw, Family::KeyboardRaw, Family::RawInputRaw,
    Family::HwndParam,
    Family::GdiRoute, Family::ObjectRaw, Family::BitmapRaw, Family::GdiBitmapRaw,
    Family::DeviceCaps, Family::BrushRaw, Family::ClipRaw, Family::GdiShape,
    Family::KeyboardQuery, Family::Legacy,
];

/// Widest Windows argument list any admitted ordinal carries, and the width of
/// the normalized array both entries build.
pub(crate) const MAX_ARGS: usize = 17;

/// How many times `ORDER` names one family. # C: O(len(ORDER))
#[cfg(test)]
pub(crate) fn walked(family: Family) -> usize {
    ORDER.iter().filter(|entry| **entry == family).count()
}

#[cfg(target_os = "oxide-kernel")]
#[path = "chain/kernel.rs"]
pub(super) mod kernel;

#[cfg(test)]
#[path = "tests/chain.rs"]
mod tests;
