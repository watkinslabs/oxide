//! Effective-child classification and what a creation `hMenu` word means.

/// POPUP wins over CHILD, matching the frozen effective-child rule. The
/// canonical window owner decides it; this is the shim's name for that call.
/// # C: O(1)
pub(crate) const fn is_effective_child(style: u32) -> bool { ipc::win32_window::is_effective_child(style) }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateMenuValue {
    None,
    ChildControlId(u64),
    MenuHandle(u64),
}

/// A child hMenu is a pointer-width control ID, never an HMENU to validate.
/// # C: O(1)
pub(crate) const fn classify_create_menu(style: u32, value: u64) -> CreateMenuValue {
    if value == 0 { CreateMenuValue::None }
    else if is_effective_child(style) { CreateMenuValue::ChildControlId(value) }
    else { CreateMenuValue::MenuHandle(value) }
}

#[cfg(test)]
#[path = "create_menu/tests.rs"]
mod tests;
