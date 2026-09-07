// Module manifest: retrieval-time hardware-message processing.
//   uapi.rs     — message numbers, activation codes, virtual keys, parameter packing
//   mouse.rs    — nonclient renumbering, double-click synthesis, filter, outcome
//   ladder.rs   — the parent-notify / mouse-activate / set-cursor step machine
//   keyboard.rs — generic-key collapse and the three removal-time extra messages
//
// A queued mouse or keyboard message is not what the application receives: the
// retrieval decides activation, the cursor and the double click on the way out
// of the queue, entering the window procedure for each decision. Deciding any
// of it at post time answers before the window procedure has been asked.
#[path = "hardware/uapi.rs"] mod uapi;
#[path = "hardware/mouse.rs"] mod mouse;
#[path = "hardware/ladder.rs"] mod ladder;
#[path = "hardware/keyboard.rs"] mod keyboard;

pub use uapi::{WM_MOUSEACTIVATE, WM_PARENTNOTIFY, WM_KEYF1, WM_CONTEXTMENU, WM_APPCOMMAND, WM_CHAR, FAPPCOMMAND_KEY,
    MA_ACTIVATE, MA_ACTIVATEANDEAT, MA_NOACTIVATE, MA_NOACTIVATEANDEAT,
    SM_CXDOUBLECLK, SM_CYDOUBLECLK, CS_DBLCLKS, WS_CHILD, WS_POPUP,
    WM_KEYFIRST, WM_KEYLAST, WM_UNICHAR, WM_MOUSEMOVE, WM_MOUSELAST, WM_NCMOUSEMOVE, WM_NCMOUSELAST,
    is_hardware_message, is_keyboard_message, is_mouse_message, is_button_down, make_point, make_hit_param, split_point};
pub use mouse::{ClickRecord, ClickUpdate, MouseContext, MouseOutcome, MousePrepared, is_double_click, prepare as prepare_mouse};
pub use ladder::{Ladder, LadderContext, LadderStep, ProcCall};
pub use keyboard::{KeyContext, KeyExtra, KeyOutcome, KeyPrepared, generic_key, prepare as prepare_key};

#[cfg(test)]
#[path = "hardware/tests/mouse.rs"]
mod mouse_tests;
#[cfg(test)]
#[path = "hardware/tests/ladder.rs"]
mod ladder_tests;
#[cfg(test)]
#[path = "hardware/tests/keyboard.rs"]
mod keyboard_tests;
