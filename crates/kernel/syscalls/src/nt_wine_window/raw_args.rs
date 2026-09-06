//! Existing raw win32u admission and x86-64 register conversion. 31d§1, 54§2.

// Logical parameter counts; stack parameters beyond index 5 remain handler-owned.
const RAW_CALLS: &[(u64, usize)] = &[
    (0x10a2, 4), // NtGdiCombineRgn
    (0x10a7, 5), // NtGdiCreateBitmap
    (0x10ae, 1), // NtGdiCreateCompatibleDC
    (0x10b9, 3), // NtGdiCreatePatternBrushInternal
    (0x10ba, 4), // NtGdiCreatePen
    (0x10bb, 4), // NtGdiCreateRectRgn
    (0x10bf, 2), // NtGdiCreateSolidBrush
    (0x118f, 1), // NtGdiDeleteObjectApp
    (0x11c7, 3), // NtGdiExtGetObjectW
    (0x11c9, 9), // NtGdiExtTextOutW
    (0x11da, 4), // NtGdiGetAndSetDCDword
    (0x11db, 2), // NtGdiGetAppClipBox
    (0x11ef, 3), // NtGdiGetDCDword
    (0x11f0, 2), // NtGdiGetDCObject
    (0x121e, 2), // NtGdiGetRgnBox
    (0x1227, 8), // NtGdiGetTextExtentExW
    (0x1229, 3), // NtGdiGetTextMetricsW
    (0x1233, 5), // NtGdiHfontCreate
    (0x1238, 5), // NtGdiIntersectClipRect
    (0x123a, 3), // NtGdiLineTo
    (0x1243, 4), // NtGdiMoveTo
    // The Windows signature carries eight arguments; the spool handle and the
    // two driver records past index 4 belong to the printer and metafile
    // drivers this call refuses, so no stack word past `is_display` is read.
    (0x1246, 5), // NtGdiOpenDCW
    (0x124c, 6), // NtGdiPatBlt
    (0x1258, 2), // NtGdiRectVisible
    (0x1259, 5), // NtGdiRectangle
    (0x126c, 2), // NtGdiSelectBrush
    (0x126e, 2), // NtGdiSelectFont
    (0x126f, 2), // NtGdiSelectPen
    (0x1287, 5), // NtGdiSetRectRgn
    (0x1327, 2), // NtUserBeginPaint
    (0x1332, 2), // NtUserCallHwnd
    (0x1336, 3), // NtUserCallHwndParam
    (0x133a, 2), // NtUserCallMsgFilter
    (0x133c, 1), // NtUserCallNoParam
    (0x133d, 2), // NtUserCallOneParam
    (0x133e, 3), // NtUserCallTwoParam
    (0x1347, 3), // NtUserCheckMenuItem
    (0x1351, 0), // NtUserCloseClipboard
    (0x135a, 3), // NtUserCopyAcceleratorTable
    (0x135c, 2), // NtUserCreateAcceleratorTable
    (0x1360, 4), // NtUserCreateCaret
    (0x1366, 0), // NtUserCreateMenu
    (0x1368, 0), // NtUserCreatePopupMenu
    (0x136b, 17), // NtUserCreateWindowEx
    (0x1378, 3), // NtUserDeleteMenu
    (0x137b, 1), // NtUserDestroyAcceleratorTable
    (0x137e, 0), // NtUserDestroyCaret
    (0x1382, 1), // NtUserDestroyMenu
    (0x1384, 1), // NtUserDestroyWindow
    (0x138b, 1), // NtUserDispatchMessage
    (0x139b, 1), // NtUserDrawMenuBar
    (0x139c, 5), // NtUserDrawMenuBarTemp
    (0x13a7, 3), // NtUserEnableMenuItem
    (0x13bc, 2), // NtUserEndPaint
    (0x13d0, 1), // NtUserGetAsyncKeyState
    (0x13d5, 0), // NtUserGetCaretBlinkTime
    (0x13d6, 1), // NtUserGetCaretPos
    // The fifth Windows argument is the ANSI flag.  The Oxide class-info
    // backend has one canonical Unicode representation and does not consume
    // that trailing flag; do not make the syscall depend on a user-stack
    // word that is outside the backend contract.
    (0x13d8, 4), // NtUserGetClassInfoEx
    (0x13d9, 3), // NtUserGetClassName
    (0x13e7, 0), // NtUserGetCursor
    (0x13eb, 1), // NtUserGetDC
    (0x13ec, 3), // NtUserGetDCEx
    (0x1410, 1), // NtUserGetKeyState
    (0x1414, 1), // NtUserGetKeyboardState
    (0x1418, 4), // NtUserGetMenuBarInfo
    (0x141a, 4), // NtUserGetMenuItemRect
    (0x141b, 4), // NtUserGetMessage
    (0x1435, 1), // NtUserGetProcessDpiAwarenessContext
    (0x1438, 2), // NtUserGetProp
    (0x144b, 1), // NtUserGetSystemDpiForProcess
    (0x1463, 2), // NtUserGetWindowPlacement
    (0x146c, 1), // NtUserHideCaret
    (0x147a, 4), // NtUserInitializeClientPfnArrays
    (0x148c, 3), // NtUserInvalidateRect
    (0x14b5, 7), // NtUserMessageCall
    (0x14ba, 6), // NtUserMoveWindow
    (0x14c2, 2), // NtUserOpenClipboard
    (0x14ca, 5), // NtUserPeekMessage
    (0x14d0, 4), // NtUserPostMessage
    (0x14e9, 4), // NtUserRedrawWindow
    (0x14eb, 7), // NtUserRegisterClassExWOW
    (0x1507, 1), // NtUserRegisterWindowMessage
    (0x1509, 2), // NtUserReleaseDC
    (0x151d, 3), // NtUserRemoveMenu
    (0x151e, 2), // NtUserRemoveProp
    (0x1532, 1), // NtUserSetActiveWindow
    (0x153b, 1), // NtUserSetCaretBlinkTime
    (0x153c, 2), // NtUserSetCaretPos
    (0x153e, 4), // NtUserSetClassLong
    (0x153f, 4), // NtUserSetClassLongPtr
    (0x1540, 3), // NtUserSetClassWord
    (0x1546, 1), // NtUserSetCursor
    (0x1557, 1), // NtUserSetFocus
    (0x1565, 1), // NtUserSetKeyboardState
    (0x1569, 2), // NtUserSetMenu
    (0x1577, 2), // NtUserSetProcessDpiAwarenessContext
    (0x157f, 3), // NtUserSetProp
    (0x1581, 4), // NtUserSetScrollInfo
    (0x15a3, 4), // NtUserSetWindowLong
    (0x15a4, 4), // NtUserSetWindowLongPtr
    (0x15a6, 2), // NtUserSetWindowPlacement
    (0x15a7, 7), // NtUserSetWindowPos
    (0x15ad, 3), // NtUserSetWindowWord
    (0x15b7, 1), // NtUserShowCaret
    (0x15bd, 2), // NtUserShowWindow
    (0x15cb, 4), // NtUserSystemParametersInfo
    (0x15d0, 6), // NtUserThunkedMenuItemInfo
    (0x15d7, 3), // NtUserTranslateAccelerator
    (0x15d8, 2), // NtUserTranslateMessage
];

/// # C: O(log(number of admitted ordinals))
pub(crate) fn argument_count(ordinal: u64) -> Option<usize> {
    if let Some(count) = crate::nt_wine_font_query_contract::argument_count(ordinal) { return Some(count); }
    RAW_CALLS.binary_search_by_key(&ordinal, |entry| entry.0).ok().map(|index| RAW_CALLS[index].1)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Decoded {
    Unclaimed,
    StackFault(usize),
    Ready([u64; 6]),
}

/// Linux snapshot is RDI,RSI,RDX,R10,R8,R9. Read logical stack indexes 4/5
/// only when present in the admitted signature. Reader owns checked usercopy
/// at saved entry RSP+0x28/0x30. No tagged selector is admitted or converted.
/// # C: O(log(number of admitted ordinals)) plus at most two stack reads
pub(crate) fn decode_x64(ordinal: u64, linux: [u64; 6], mut stack: impl FnMut(usize) -> Option<u64>) -> Decoded {
    let Some(count) = argument_count(ordinal) else { return Decoded::Unclaimed; };
    let mut args = [linux[3], linux[2], linux[4], linux[5], 0, 0];
    for index in 4..count.min(args.len()) {
        let Some(value) = stack(index) else { return Decoded::StackFault(index); };
        args[index] = value;
    }
    Decoded::Ready(args)
}

#[cfg(test)]
#[path = "tests/raw_args.rs"]
mod tests;
