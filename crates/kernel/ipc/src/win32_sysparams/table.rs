//! The session-wide system-parameter entries, each with the actions that read
//! and write it and the default it carries before anything writes one.
//!
//! Dimension entries are quoted the way the reference quotes them: a negative
//! stored value is twips, a positive one is already pixels. 1440 twips is one
//! inch, so a twips value becomes pixels against the display's dots per inch.

/// Action number that names no entry side. Zero is not an action.
pub const NO_ACTION: u32 = 0;
/// Twips in one inch.
pub const TWIPS_PER_INCH: i64 = 1440;
/// Dots per inch the profile is quoted at before any per-monitor scaling.
pub const DEFAULT_DPI: u32 = 96;

/// How a stored value is quoted.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    /// The stored value is the value, whatever its unit.
    Word,
    /// Negative is twips, positive is pixels.
    Twips,
}

/// One system-parameter entry: the action that reads it, the action that
/// writes it, how its stored value is quoted, and the value it starts at.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Entry { pub get: u32, pub set: u32, pub kind: Kind, pub default: i32 }

const fn word(get: u32, set: u32, default: i32) -> Entry { Entry { get, set, kind: Kind::Word, default } }
const fn twips(get: u32, set: u32, default: i32) -> Entry { Entry { get, set, kind: Kind::Twips, default } }

/// Every scalar entry, in slot order. The slot of an entry is its index here,
/// and a stored value lives at that index; nothing else keys these values, so
/// a getter and its setter cannot reach different storage.
pub const ENTRIES: &[Entry] = &[
    word(NO_ACTION, NO_ACTION, 1),                                   // warning beep: the window owner holds it
    word(NO_ACTION, NO_ACTION, 6),                                   // mouse threshold 1
    word(NO_ACTION, NO_ACTION, 10),                                  // mouse threshold 2
    word(NO_ACTION, NO_ACTION, 1),                                   // mouse acceleration
    twips(a::GET_BORDER, a::SET_BORDER, -15),
    word(a::GET_KEYBOARD_SPEED, a::SET_KEYBOARD_SPEED, 31),
    twips(NO_ACTION, NO_ACTION, -1125),                              // icon horizontal spacing
    word(a::GET_SCREEN_SAVE_TIMEOUT, a::SET_SCREEN_SAVE_TIMEOUT, 300),
    word(a::GET_SCREEN_SAVE_ACTIVE, a::SET_SCREEN_SAVE_ACTIVE, 1),
    word(a::GET_GRID_GRANULARITY, a::SET_GRID_GRANULARITY, 0),
    word(a::GET_KEYBOARD_DELAY, a::SET_KEYBOARD_DELAY, 1),
    twips(NO_ACTION, NO_ACTION, -1125),                              // icon vertical spacing
    word(a::GET_ICON_TITLE_WRAP, a::SET_ICON_TITLE_WRAP, 1),
    word(a::GET_MENU_DROP_ALIGNMENT, a::SET_MENU_DROP_ALIGNMENT, 0),
    word(NO_ACTION, a::SET_DOUBLE_CLK_WIDTH, 4),
    word(NO_ACTION, a::SET_DOUBLE_CLK_HEIGHT, 4),
    word(NO_ACTION, NO_ACTION, 500),                                 // double-click interval: the window owner holds it
    word(NO_ACTION, a::SET_MOUSE_BUTTON_SWAP, 0),
    word(a::GET_DRAG_FULL_WINDOWS, a::SET_DRAG_FULL_WINDOWS, 0),
    twips(NO_ACTION, NO_ACTION, 0),                                  // padded border width
    twips(NO_ACTION, NO_ACTION, -240),                               // scroll width
    twips(NO_ACTION, NO_ACTION, -240),                               // scroll height
    twips(NO_ACTION, NO_ACTION, -270),                               // caption width
    twips(NO_ACTION, NO_ACTION, -270),                               // caption height
    twips(NO_ACTION, NO_ACTION, -225),                               // small caption width
    twips(NO_ACTION, NO_ACTION, -225),                               // small caption height
    twips(NO_ACTION, NO_ACTION, -270),                               // menu width
    twips(NO_ACTION, NO_ACTION, -270),                               // menu height
    word(NO_ACTION, NO_ACTION, 154),                                 // minimized width
    word(NO_ACTION, NO_ACTION, 0),                                   // minimized horizontal gap
    word(NO_ACTION, NO_ACTION, 0),                                   // minimized vertical gap
    word(NO_ACTION, NO_ACTION, 8),                                   // minimized arrangement
    word(a::GET_SHOW_SOUNDS, a::SET_SHOW_SOUNDS, 0),
    word(a::GET_KEYBOARD_PREF, a::SET_KEYBOARD_PREF, 1),
    word(a::GET_SCREEN_READER, a::SET_SCREEN_READER, 0),
    word(a::GET_FONT_SMOOTHING, a::SET_FONT_SMOOTHING, 2),
    word(NO_ACTION, a::SET_DRAG_WIDTH, 4),
    word(NO_ACTION, a::SET_DRAG_HEIGHT, 4),
    word(a::GET_LOW_POWER_ACTIVE, a::SET_LOW_POWER_ACTIVE, 0),
    word(a::GET_POWER_OFF_ACTIVE, a::SET_POWER_OFF_ACTIVE, 0),
    word(a::GET_MOUSE_TRAILS, a::SET_MOUSE_TRAILS, 0),
    word(a::GET_SNAP_TO_DEF_BUTTON, a::SET_SNAP_TO_DEF_BUTTON, 0),
    word(a::GET_SCREEN_SAVER_RUNNING, a::SET_SCREEN_SAVER_RUNNING, 0),
    word(a::GET_MOUSE_HOVER_WIDTH, a::SET_MOUSE_HOVER_WIDTH, 4),
    word(a::GET_MOUSE_HOVER_HEIGHT, a::SET_MOUSE_HOVER_HEIGHT, 4),
    word(NO_ACTION, NO_ACTION, 400),                                 // hover dwell: the window owner holds it
    word(a::GET_WHEEL_SCROLL_LINES, a::SET_WHEEL_SCROLL_LINES, 3),
    word(a::GET_MENU_SHOW_DELAY, a::SET_MENU_SHOW_DELAY, 400),
    word(a::GET_WHEEL_SCROLL_CHARS, a::SET_WHEEL_SCROLL_CHARS, 3),
    word(a::GET_MOUSE_SPEED, a::SET_MOUSE_SPEED, 10),
    word(a::GET_ACTIVE_WINDOW_TRACKING, a::SET_ACTIVE_WINDOW_TRACKING, 0),
    word(a::GET_MENU_ANIMATION, a::SET_MENU_ANIMATION, 0),
    word(a::GET_COMBO_BOX_ANIMATION, a::SET_COMBO_BOX_ANIMATION, 0),
    word(a::GET_LISTBOX_SMOOTH_SCROLLING, a::SET_LISTBOX_SMOOTH_SCROLLING, 0),
    word(a::GET_GRADIENT_CAPTIONS, a::SET_GRADIENT_CAPTIONS, 1),
    word(a::GET_KEYBOARD_CUES, a::SET_KEYBOARD_CUES, 0),
    word(a::GET_ACTIVE_WND_TRK_ZORDER, a::SET_ACTIVE_WND_TRK_ZORDER, 0),
    word(a::GET_HOT_TRACKING, a::SET_HOT_TRACKING, 0),
    word(a::GET_MENU_FADE, a::SET_MENU_FADE, 0),
    word(a::GET_SELECTION_FADE, a::SET_SELECTION_FADE, 0),
    word(a::GET_TOOLTIP_ANIMATION, a::SET_TOOLTIP_ANIMATION, 0),
    word(a::GET_TOOLTIP_FADE, a::SET_TOOLTIP_FADE, 0),
    word(a::GET_CURSOR_SHADOW, a::SET_CURSOR_SHADOW, 0),
    word(a::GET_MOUSE_SONAR, a::SET_MOUSE_SONAR, 0),
    word(a::GET_MOUSE_CLICK_LOCK, a::SET_MOUSE_CLICK_LOCK, 0),
    word(a::GET_MOUSE_VANISH, a::SET_MOUSE_VANISH, 0),
    word(a::GET_FLAT_MENU, a::SET_FLAT_MENU, 0),
    word(a::GET_DROP_SHADOW, a::SET_DROP_SHADOW, 0),
    word(a::GET_BLOCK_SEND_INPUT_RESETS, a::SET_BLOCK_SEND_INPUT_RESETS, 0),
    word(a::GET_UI_EFFECTS, a::SET_UI_EFFECTS, 1),
    word(a::GET_DISABLE_OVERLAPPED_CONTENT, a::SET_DISABLE_OVERLAPPED_CONTENT, 0),
    word(a::GET_CLIENT_AREA_ANIMATION, a::SET_CLIENT_AREA_ANIMATION, 1),
    word(a::GET_CLEARTYPE, a::SET_CLEARTYPE, 1),
    word(a::GET_SPEECH_RECOGNITION, a::SET_SPEECH_RECOGNITION, 0),
    word(a::GET_FOREGROUND_LOCK_TIMEOUT, a::SET_FOREGROUND_LOCK_TIMEOUT, 0),
    word(a::GET_ACTIVE_WND_TRK_TIMEOUT, NO_ACTION, 0),
    word(a::GET_FOREGROUND_FLASH_COUNT, a::SET_FOREGROUND_FLASH_COUNT, 3),
    word(a::GET_CARET_WIDTH, a::SET_CARET_WIDTH, 1),
    word(a::GET_MOUSE_CLICK_LOCK_TIME, a::SET_MOUSE_CLICK_LOCK_TIME, 1200),
    word(a::GET_FONT_SMOOTHING_TYPE, a::SET_FONT_SMOOTHING_TYPE, 1),
    word(a::GET_FONT_SMOOTHING_CONTRAST, a::SET_FONT_SMOOTHING_CONTRAST, 0),
    word(a::GET_FOCUS_BORDER_WIDTH, a::SET_FOCUS_BORDER_WIDTH, 1),
    word(a::GET_FOCUS_BORDER_HEIGHT, a::SET_FOCUS_BORDER_HEIGHT, 1),
    word(a::GET_FONT_SMOOTHING_ORIENTATION, a::SET_FONT_SMOOTHING_ORIENTATION, 1),
];

/// Slots the struct-shaped actions name directly, in `ENTRIES` order.
pub mod slot {
    pub const MOUSE_THRESHOLD1: usize = 1;
    pub const MOUSE_THRESHOLD2: usize = 2;
    pub const MOUSE_ACCELERATION: usize = 3;
    pub const BORDER: usize = 4;
    pub const ICON_HORIZONTAL_SPACING: usize = 6;
    pub const ICON_VERTICAL_SPACING: usize = 11;
    pub const ICON_TITLE_WRAP: usize = 12;
    pub const PADDED_BORDER_WIDTH: usize = 19;
    pub const SCROLL_WIDTH: usize = 20;
    pub const SCROLL_HEIGHT: usize = 21;
    pub const CAPTION_WIDTH: usize = 22;
    pub const CAPTION_HEIGHT: usize = 23;
    pub const SM_CAPTION_WIDTH: usize = 24;
    pub const SM_CAPTION_HEIGHT: usize = 25;
    pub const MENU_WIDTH: usize = 26;
    pub const MENU_HEIGHT: usize = 27;
    pub const MIN_WIDTH: usize = 28;
    pub const MIN_HORZ_GAP: usize = 29;
    pub const MIN_VERT_GAP: usize = 30;
    pub const MIN_ARRANGE: usize = 31;
}

/// Action numbers, as the window ABI publishes them.
pub mod a {
    pub const GET_BEEP: u32 = 1;
    pub const SET_BEEP: u32 = 2;
    pub const GET_MOUSE: u32 = 3;
    pub const SET_MOUSE: u32 = 4;
    pub const GET_BORDER: u32 = 5;
    pub const SET_BORDER: u32 = 6;
    pub const GET_KEYBOARD_SPEED: u32 = 10;
    pub const SET_KEYBOARD_SPEED: u32 = 11;
    pub const ICON_HORIZONTAL_SPACING: u32 = 13;
    pub const GET_SCREEN_SAVE_TIMEOUT: u32 = 14;
    pub const SET_SCREEN_SAVE_TIMEOUT: u32 = 15;
    pub const GET_SCREEN_SAVE_ACTIVE: u32 = 16;
    pub const SET_SCREEN_SAVE_ACTIVE: u32 = 17;
    pub const GET_GRID_GRANULARITY: u32 = 18;
    pub const SET_GRID_GRANULARITY: u32 = 19;
    pub const SET_DESK_WALLPAPER: u32 = 20;
    pub const GET_KEYBOARD_DELAY: u32 = 22;
    pub const SET_KEYBOARD_DELAY: u32 = 23;
    pub const ICON_VERTICAL_SPACING: u32 = 24;
    pub const GET_ICON_TITLE_WRAP: u32 = 25;
    pub const SET_ICON_TITLE_WRAP: u32 = 26;
    pub const GET_MENU_DROP_ALIGNMENT: u32 = 27;
    pub const SET_MENU_DROP_ALIGNMENT: u32 = 28;
    pub const SET_DOUBLE_CLK_WIDTH: u32 = 29;
    pub const SET_DOUBLE_CLK_HEIGHT: u32 = 30;
    pub const GET_ICON_TITLE_LOGFONT: u32 = 31;
    pub const SET_DOUBLE_CLICK_TIME: u32 = 32;
    pub const SET_MOUSE_BUTTON_SWAP: u32 = 33;
    pub const SET_ICON_TITLE_LOGFONT: u32 = 34;
    pub const GET_FAST_TASK_SWITCH: u32 = 35;
    pub const SET_FAST_TASK_SWITCH: u32 = 36;
    pub const SET_DRAG_FULL_WINDOWS: u32 = 37;
    pub const GET_DRAG_FULL_WINDOWS: u32 = 38;
    pub const GET_NONCLIENT_METRICS: u32 = 41;
    pub const SET_NONCLIENT_METRICS: u32 = 42;
    pub const GET_MINIMIZED_METRICS: u32 = 43;
    pub const SET_MINIMIZED_METRICS: u32 = 44;
    pub const GET_ICON_METRICS: u32 = 45;
    pub const SET_ICON_METRICS: u32 = 46;
    pub const GET_SHOW_SOUNDS: u32 = 56;
    pub const SET_SHOW_SOUNDS: u32 = 57;
    pub const GET_KEYBOARD_PREF: u32 = 68;
    pub const SET_KEYBOARD_PREF: u32 = 69;
    pub const GET_SCREEN_READER: u32 = 70;
    pub const SET_SCREEN_READER: u32 = 71;
    pub const GET_FONT_SMOOTHING: u32 = 74;
    pub const SET_FONT_SMOOTHING: u32 = 75;
    pub const SET_DRAG_WIDTH: u32 = 76;
    pub const SET_DRAG_HEIGHT: u32 = 77;
    pub const GET_LOW_POWER_ACTIVE: u32 = 83;
    pub const GET_POWER_OFF_ACTIVE: u32 = 84;
    pub const SET_LOW_POWER_ACTIVE: u32 = 85;
    pub const SET_POWER_OFF_ACTIVE: u32 = 86;
    pub const SET_MOUSE_TRAILS: u32 = 93;
    pub const GET_MOUSE_TRAILS: u32 = 94;
    pub const GET_SNAP_TO_DEF_BUTTON: u32 = 95;
    pub const SET_SNAP_TO_DEF_BUTTON: u32 = 96;
    pub const SET_SCREEN_SAVER_RUNNING: u32 = 97;
    pub const GET_MOUSE_HOVER_WIDTH: u32 = 98;
    pub const SET_MOUSE_HOVER_WIDTH: u32 = 99;
    pub const GET_MOUSE_HOVER_HEIGHT: u32 = 100;
    pub const SET_MOUSE_HOVER_HEIGHT: u32 = 101;
    pub const GET_MOUSE_HOVER_TIME: u32 = 102;
    pub const SET_MOUSE_HOVER_TIME: u32 = 103;
    pub const GET_WHEEL_SCROLL_LINES: u32 = 104;
    pub const SET_WHEEL_SCROLL_LINES: u32 = 105;
    pub const GET_MENU_SHOW_DELAY: u32 = 106;
    pub const SET_MENU_SHOW_DELAY: u32 = 107;
    pub const GET_WHEEL_SCROLL_CHARS: u32 = 108;
    pub const SET_WHEEL_SCROLL_CHARS: u32 = 109;
    pub const GET_MOUSE_SPEED: u32 = 112;
    pub const SET_MOUSE_SPEED: u32 = 113;
    pub const GET_SCREEN_SAVER_RUNNING: u32 = 114;
    pub const GET_DESK_WALLPAPER: u32 = 115;
    pub const GET_ACTIVE_WINDOW_TRACKING: u32 = 0x1000;
    pub const SET_ACTIVE_WINDOW_TRACKING: u32 = 0x1001;
    pub const GET_MENU_ANIMATION: u32 = 0x1002;
    pub const SET_MENU_ANIMATION: u32 = 0x1003;
    pub const GET_COMBO_BOX_ANIMATION: u32 = 0x1004;
    pub const SET_COMBO_BOX_ANIMATION: u32 = 0x1005;
    pub const GET_LISTBOX_SMOOTH_SCROLLING: u32 = 0x1006;
    pub const SET_LISTBOX_SMOOTH_SCROLLING: u32 = 0x1007;
    pub const GET_GRADIENT_CAPTIONS: u32 = 0x1008;
    pub const SET_GRADIENT_CAPTIONS: u32 = 0x1009;
    pub const GET_KEYBOARD_CUES: u32 = 0x100a;
    pub const SET_KEYBOARD_CUES: u32 = 0x100b;
    pub const GET_ACTIVE_WND_TRK_ZORDER: u32 = 0x100c;
    pub const SET_ACTIVE_WND_TRK_ZORDER: u32 = 0x100d;
    pub const GET_HOT_TRACKING: u32 = 0x100e;
    pub const SET_HOT_TRACKING: u32 = 0x100f;
    pub const GET_MENU_FADE: u32 = 0x1012;
    pub const SET_MENU_FADE: u32 = 0x1013;
    pub const GET_SELECTION_FADE: u32 = 0x1014;
    pub const SET_SELECTION_FADE: u32 = 0x1015;
    pub const GET_TOOLTIP_ANIMATION: u32 = 0x1016;
    pub const SET_TOOLTIP_ANIMATION: u32 = 0x1017;
    pub const GET_TOOLTIP_FADE: u32 = 0x1018;
    pub const SET_TOOLTIP_FADE: u32 = 0x1019;
    pub const GET_CURSOR_SHADOW: u32 = 0x101a;
    pub const SET_CURSOR_SHADOW: u32 = 0x101b;
    pub const GET_MOUSE_SONAR: u32 = 0x101c;
    pub const SET_MOUSE_SONAR: u32 = 0x101d;
    pub const GET_MOUSE_CLICK_LOCK: u32 = 0x101e;
    pub const SET_MOUSE_CLICK_LOCK: u32 = 0x101f;
    pub const GET_MOUSE_VANISH: u32 = 0x1020;
    pub const SET_MOUSE_VANISH: u32 = 0x1021;
    pub const GET_FLAT_MENU: u32 = 0x1022;
    pub const SET_FLAT_MENU: u32 = 0x1023;
    pub const GET_DROP_SHADOW: u32 = 0x1024;
    pub const SET_DROP_SHADOW: u32 = 0x1025;
    pub const GET_BLOCK_SEND_INPUT_RESETS: u32 = 0x1026;
    pub const SET_BLOCK_SEND_INPUT_RESETS: u32 = 0x1027;
    pub const GET_UI_EFFECTS: u32 = 0x103e;
    pub const SET_UI_EFFECTS: u32 = 0x103f;
    pub const GET_DISABLE_OVERLAPPED_CONTENT: u32 = 0x1040;
    pub const SET_DISABLE_OVERLAPPED_CONTENT: u32 = 0x1041;
    pub const GET_CLIENT_AREA_ANIMATION: u32 = 0x1042;
    pub const SET_CLIENT_AREA_ANIMATION: u32 = 0x1043;
    pub const GET_CLEARTYPE: u32 = 0x1048;
    pub const SET_CLEARTYPE: u32 = 0x1049;
    pub const GET_SPEECH_RECOGNITION: u32 = 0x104a;
    pub const SET_SPEECH_RECOGNITION: u32 = 0x104b;
    pub const GET_FOREGROUND_LOCK_TIMEOUT: u32 = 0x2000;
    pub const SET_FOREGROUND_LOCK_TIMEOUT: u32 = 0x2001;
    pub const GET_ACTIVE_WND_TRK_TIMEOUT: u32 = 0x2002;
    pub const GET_FOREGROUND_FLASH_COUNT: u32 = 0x2004;
    pub const SET_FOREGROUND_FLASH_COUNT: u32 = 0x2005;
    pub const GET_CARET_WIDTH: u32 = 0x2006;
    pub const SET_CARET_WIDTH: u32 = 0x2007;
    pub const GET_MOUSE_CLICK_LOCK_TIME: u32 = 0x2008;
    pub const SET_MOUSE_CLICK_LOCK_TIME: u32 = 0x2009;
    pub const GET_FONT_SMOOTHING_TYPE: u32 = 0x200a;
    pub const SET_FONT_SMOOTHING_TYPE: u32 = 0x200b;
    pub const GET_FONT_SMOOTHING_CONTRAST: u32 = 0x200c;
    pub const SET_FONT_SMOOTHING_CONTRAST: u32 = 0x200d;
    pub const GET_FOCUS_BORDER_WIDTH: u32 = 0x200e;
    pub const SET_FOCUS_BORDER_WIDTH: u32 = 0x200f;
    pub const GET_FOCUS_BORDER_HEIGHT: u32 = 0x2010;
    pub const SET_FOCUS_BORDER_HEIGHT: u32 = 0x2011;
    pub const GET_FONT_SMOOTHING_ORIENTATION: u32 = 0x2012;
    pub const SET_FONT_SMOOTHING_ORIENTATION: u32 = 0x2013;
}
