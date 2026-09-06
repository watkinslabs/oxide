//! Builtin window classes (Button, Edit, Static, ...). The reference registers
//! them from win32u once per process with procedures taken from the client
//! procedure arrays user32 publishes; applications never register them.
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
pub(crate) struct Builtin { pub name: &'static str, pub style: u32, pub extra: i32, pub brush: u64, pub proc_index: usize }

/// Reference order; the 64-bit Edit carries a pointer-sized extra. # C: O(1)
pub(crate) const BUILTINS: [Builtin; 12] = [
    Builtin { name: "Button", style: CS_DBLCLKS | CS_VREDRAW | CS_HREDRAW | CS_PARENTDC, extra: 4 + 2 * HANDLE, brush: 0, proc_index: PROC_BUTTON },
    Builtin { name: "ComboBox", style: CS_PARENTDC | CS_DBLCLKS | CS_HREDRAW | CS_VREDRAW, extra: POINTER, brush: 0, proc_index: PROC_COMBO },
    Builtin { name: "ComboLBox", style: CS_DBLCLKS | CS_SAVEBITS, extra: POINTER, brush: 0, proc_index: PROC_COMBOLBOX },
    Builtin { name: "#32770", style: CS_SAVEBITS | CS_DBLCLKS, extra: DLGWINDOWEXTRA, brush: 0, proc_index: PROC_DIALOG },
    Builtin { name: "#32772", style: 0, extra: 0, brush: 0, proc_index: PROC_ICONTITLE },
    Builtin { name: "IME", style: 0, extra: 2 * POINTER, brush: 0, proc_index: PROC_IME },
    Builtin { name: "ListBox", style: CS_DBLCLKS, extra: POINTER, brush: 0, proc_index: PROC_LISTBOX },
    Builtin { name: "#32768", style: CS_DROPSHADOW | CS_SAVEBITS | CS_DBLCLKS, extra: HANDLE, brush: COLOR_MENU + 1, proc_index: PROC_MENU },
    Builtin { name: "MDIClient", style: 0, extra: 2 * POINTER, brush: COLOR_APPWORKSPACE + 1, proc_index: PROC_MDICLIENT },
    Builtin { name: "ScrollBar", style: CS_DBLCLKS | CS_VREDRAW | CS_HREDRAW | CS_PARENTDC, extra: SCROLL_BAR_WIN_DATA, brush: 0, proc_index: PROC_SCROLLBAR },
    Builtin { name: "Static", style: CS_DBLCLKS | CS_PARENTDC, extra: 2 * HANDLE, brush: 0, proc_index: PROC_STATIC },
    Builtin { name: "Edit", style: CS_DBLCLKS | CS_PARENTDC, extra: POINTER, brush: 0, proc_index: PROC_EDIT },
];

/// Register every builtin whose procedure the array provides; `procedure`
/// reads one array entry, `register` admits one class. Returns how many were
/// registered. # C: O(builtins)
pub(crate) fn register_all(mut procedure: impl FnMut(usize) -> Option<u64>, mut register: impl FnMut(&Builtin, u64) -> bool) -> usize {
    let mut registered = 0;
    for builtin in &BUILTINS {
        let Some(wndproc) = procedure(builtin.proc_index).filter(|proc| *proc != 0) else { continue; };
        if register(builtin, wndproc) { registered += 1; }
    }
    registered
}

#[cfg(target_os = "oxide-kernel")]
#[path = "builtin_classes/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path = "tests/builtin_classes.rs"]
mod tests;
