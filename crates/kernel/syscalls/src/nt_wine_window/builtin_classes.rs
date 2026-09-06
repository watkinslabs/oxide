//! Builtin window classes (Button, Edit, Static, ...). The reference registers
//! them from win32u once per process with procedures taken from the client
//! procedure arrays user32 publishes; applications never register them.
use ipc::win32_window::{IDC_ARROW, IDC_IBEAM};
pub(crate) const CS_VREDRAW: u32 = 0x0001;
pub(crate) const CS_HREDRAW: u32 = 0x0002;
pub(crate) const CS_DBLCLKS: u32 = 0x0008;
pub(crate) const CS_PARENTDC: u32 = 0x0080;
pub(crate) const CS_SAVEBITS: u32 = 0x0800;
pub(crate) const CS_DROPSHADOW: u32 = 0x0002_0000;
const COLOR_MENU: u64 = 4;
const COLOR_APPWORKSPACE: u64 = 12;
const DLGWINDOWEXTRA: i32 = 30;
const POINTER: i32 = 8;
const HANDLE: i32 = 8;
/// DWORD magic plus six 32-bit scroll fields.
const SCROLL_BAR_WIN_DATA: i32 = 4 + 6 * 4;
/// Client procedure array indices (`NTUSER_WNDPROC_*`).
pub(crate) const PROC_SCROLLBAR: usize = 0;
pub(crate) const PROC_MENU: usize = 2;
pub(crate) const PROC_ICONTITLE: usize = 5;
pub(crate) const PROC_BUTTON: usize = 7;
pub(crate) const PROC_COMBO: usize = 8;
pub(crate) const PROC_COMBOLBOX: usize = 9;
pub(crate) const PROC_DIALOG: usize = 10;
pub(crate) const PROC_EDIT: usize = 11;
pub(crate) const PROC_LISTBOX: usize = 12;
pub(crate) const PROC_MDICLIENT: usize = 13;
pub(crate) const PROC_STATIC: usize = 14;
pub(crate) const PROC_IME: usize = 15;
pub(crate) const PROC_COUNT: usize = 17;
pub(crate) const PROC_ENTRY_BYTES: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Builtin { pub name: &'static str, pub style: u32, pub extra: i32, pub brush: u64, pub proc_index: usize,
    /// OEM cursor resource the class loads shared at registration.
    pub cursor: u32 }

/// Reference order; the 64-bit Edit carries a pointer-sized extra. # C: O(1)
pub(crate) const BUILTINS: [Builtin; 12] = [
    Builtin { name: "Button", style: CS_DBLCLKS | CS_VREDRAW | CS_HREDRAW | CS_PARENTDC, extra: 4 + 2 * HANDLE, brush: 0, proc_index: PROC_BUTTON, cursor: IDC_ARROW },
    Builtin { name: "ComboBox", style: CS_PARENTDC | CS_DBLCLKS | CS_HREDRAW | CS_VREDRAW, extra: POINTER, brush: 0, proc_index: PROC_COMBO, cursor: IDC_ARROW },
    Builtin { name: "ComboLBox", style: CS_DBLCLKS | CS_SAVEBITS, extra: POINTER, brush: 0, proc_index: PROC_COMBOLBOX, cursor: IDC_ARROW },
    Builtin { name: "#32770", style: CS_SAVEBITS | CS_DBLCLKS, extra: DLGWINDOWEXTRA, brush: 0, proc_index: PROC_DIALOG, cursor: IDC_ARROW },
    Builtin { name: "#32772", style: 0, extra: 0, brush: 0, proc_index: PROC_ICONTITLE, cursor: IDC_ARROW },
    Builtin { name: "IME", style: 0, extra: 2 * POINTER, brush: 0, proc_index: PROC_IME, cursor: IDC_ARROW },
    Builtin { name: "ListBox", style: CS_DBLCLKS, extra: POINTER, brush: 0, proc_index: PROC_LISTBOX, cursor: IDC_ARROW },
    Builtin { name: "#32768", style: CS_DROPSHADOW | CS_SAVEBITS | CS_DBLCLKS, extra: HANDLE, brush: COLOR_MENU + 1, proc_index: PROC_MENU, cursor: IDC_ARROW },
    Builtin { name: "MDIClient", style: 0, extra: 2 * POINTER, brush: COLOR_APPWORKSPACE + 1, proc_index: PROC_MDICLIENT, cursor: IDC_ARROW },
    Builtin { name: "ScrollBar", style: CS_DBLCLKS | CS_VREDRAW | CS_HREDRAW | CS_PARENTDC, extra: SCROLL_BAR_WIN_DATA, brush: 0, proc_index: PROC_SCROLLBAR, cursor: IDC_ARROW },
    Builtin { name: "Static", style: CS_DBLCLKS | CS_PARENTDC, extra: 2 * HANDLE, brush: 0, proc_index: PROC_STATIC, cursor: IDC_ARROW },
    Builtin { name: "Edit", style: CS_DBLCLKS | CS_PARENTDC, extra: POINTER, brush: 0, proc_index: PROC_EDIT, cursor: IDC_IBEAM },
];

/// Register every builtin whose procedure the array provides; `procedure`
/// reads one array entry, `cursor` loads one shared OEM cursor, `register`
/// admits one class. A cursor that will not load still registers its class:
/// the reference destroys the cursor when registration fails, never the
/// reverse. Returns how many were registered. # C: O(builtins)
pub(crate) fn register_all(mut procedure: impl FnMut(usize) -> Option<u64>, mut cursor: impl FnMut(u32) -> Option<u64>,
    mut register: impl FnMut(&Builtin, u64, u64) -> bool) -> usize {
    let mut registered = 0;
    for builtin in &BUILTINS {
        let Some(wndproc) = procedure(builtin.proc_index).filter(|proc| *proc != 0) else { continue; };
        if register(builtin, wndproc, cursor(builtin.cursor).unwrap_or(0)) { registered += 1; }
    }
    registered
}

#[cfg(target_os = "oxide-kernel")]
#[path = "builtin_classes/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path = "tests/builtin_classes.rs"]
mod tests;
