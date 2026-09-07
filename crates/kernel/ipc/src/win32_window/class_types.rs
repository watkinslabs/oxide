//! The registered class record, its menu name, the description the
//! class-information query reports, and the registration a caller hands over.
use super::{WindowExtra};
use alloc::vec::Vec;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowClass { pub name: Vec<u16>, pub wndproc: u64, pub unicode: bool, pub atom: u16, pub cb_wnd_extra: u32, pub style: u32,
    /// A local class answers only the module that registered it; a class
    /// registered with CS_GLOBALCLASS, or by a builtin registration, answers
    /// every module of the process.
    pub local: bool,
    /// Raw WNDCLASSEX hbrBackground: a brush handle, or a system colour index plus one.
    pub background: u64,
    /// WNDCLASSEX hCursor. The default window procedure answers WM_SETCURSOR
    /// over HTCLIENT with it, and a class registered without one declines.
    pub cursor: u64,
    pub icon: u64, pub icon_sm: u64, pub module: u64,
    /// Client pointers to the class menu name, ANSI and wide, exactly as the
    /// registering client handed them over. An integer resource id travels as
    /// a small pointer value; the kernel never dereferences either.
    pub menu_name: ClassMenuName,
    /// cbClsExtra bytes, shared by every window of the class.
    pub extra: WindowExtra }

/// The three client pointers one class registration carries for its menu name.
/// Window creation loads the menu from whichever the caller's width names.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct ClassMenuName { pub ansi: u64, pub wide: u64, pub unicode_string: u64 }

/// Everything the class-information query reports back about one registered
/// class, in WNDCLASSEXW terms.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClassDescription { pub style: u32, pub cb_wnd_extra: u32, pub cb_cls_extra: usize,
    pub background: u64, pub cursor: u64, pub icon: u64, pub icon_sm: u64, pub module: u64,
    pub menu_name: ClassMenuName }

/// One WNDCLASSEXW registration. The telescoping helpers below fill the
/// fields a caller does not carry.
pub struct ClassRegistration<'a> { pub name: &'a [u16], pub wndproc: u64, pub cb_cls_extra: i32, pub cb_wnd_extra: i32,
    pub unicode: bool, pub style: u32, pub background: u64, pub cursor: u64, pub icon: u64, pub icon_sm: u64, pub module: u64,
    pub menu_name: ClassMenuName,
    /// A builtin registration is global whatever its style says.
    pub builtin: bool }

impl<'a> ClassRegistration<'a> {
    /// # C: O(1)
    pub const fn new(name: &'a [u16], wndproc: u64) -> Self {
        Self { name, wndproc, cb_cls_extra: 0, cb_wnd_extra: 0, unicode: true, style: 0, background: 0,
            cursor: 0, icon: 0, icon_sm: 0, module: 0, menu_name: ClassMenuName { ansi: 0, wide: 0, unicode_string: 0 },
            builtin: false }
    }
}
