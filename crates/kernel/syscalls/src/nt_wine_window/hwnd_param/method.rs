//! The `NtUserCallHwndParam` method enumeration, in the client's order.
//!
//! One list. Every routing decision reads it, so a method the client sends and
//! this file does not name is a compile-visible gap rather than a refused
//! syscall the client dereferences the answer of.

pub(crate) const CLIENT_TO_SCREEN: u32 = 0;
pub(crate) const GET_CHILD_RECT: u32 = 1;
pub(crate) const GET_CLASS_LONG_A: u32 = 2;
pub(crate) const GET_CLASS_LONG_W: u32 = 3;
pub(crate) const GET_CLASS_LONG_PTR_A: u32 = 4;
pub(crate) const GET_CLASS_LONG_PTR_W: u32 = 5;
pub(crate) const GET_CLASS_WORD: u32 = 6;
pub(crate) const GET_SCROLL_INFO: u32 = 7;
pub(crate) const GET_WINDOW_INFO: u32 = 8;
pub(crate) const GET_WINDOW_LONG_A: u32 = 9;
pub(crate) const GET_WINDOW_LONG_W: u32 = 10;
pub(crate) const GET_WINDOW_LONG_PTR_A: u32 = 11;
pub(crate) const GET_WINDOW_LONG_PTR_W: u32 = 12;
pub(crate) const GET_WINDOW_RECT: u32 = 13;
pub(crate) const GET_CLIENT_RECT: u32 = 14;
pub(crate) const GET_PRESENT_RECT: u32 = 15;
pub(crate) const GET_WINDOW_RELATIVE: u32 = 16;
pub(crate) const GET_WINDOW_THREAD: u32 = 17;
pub(crate) const GET_WINDOW_WORD: u32 = 18;
pub(crate) const IS_CHILD: u32 = 19;
pub(crate) const MAP_WINDOW_POINTS: u32 = 20;
pub(crate) const MIRROR_RGN: u32 = 21;
pub(crate) const MONITOR_FROM_WINDOW: u32 = 22;
pub(crate) const SCREEN_TO_CLIENT: u32 = 23;
pub(crate) const SET_DIALOG_INFO: u32 = 24;
pub(crate) const SET_MDI_CLIENT_INFO: u32 = 25;
pub(crate) const SEND_HARDWARE_INPUT: u32 = 26;
pub(crate) const EXPOSE_WINDOW_SURFACE: u32 = 27;
pub(crate) const GET_WIN_MONITOR_DPI: u32 = 28;
pub(crate) const SET_RAW_WINDOW_POS: u32 = 29;
pub(crate) const GET_PRIVATE_DATA: u32 = 30;
pub(crate) const SET_PRIVATE_DATA: u32 = 31;

/// Methods the enumeration holds; every index below it names one.
pub(crate) const COUNT: u32 = 32;
