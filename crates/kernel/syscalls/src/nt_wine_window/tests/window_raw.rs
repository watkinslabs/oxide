//! Window-family ordinal admission, record layouts and the flash decision.
use super::*;

#[test]
fn the_family_claims_exactly_its_own_ordinals() {
    for ordinal in [ALTER_WINDOW_STYLE, ARRANGE_ICONIC_WINDOWS, BEGIN_DEFER_WINDOW_POS, BUILD_HWND_LIST,
        BUILD_PROP_LIST, CHILD_WINDOW_FROM_POINT_EX, DEFER_WINDOW_POS_AND_BAND, ENABLE_WINDOW,
        END_DEFER_WINDOW_POS_EX, FIND_WINDOW_EX, FLASH_WINDOW_EX, GET_ANCESTOR, GET_FOREGROUND_WINDOW,
        GET_GUI_THREAD_INFO, GET_INTERNAL_WINDOW_POS, GET_LAYERED_ATTRIBUTES, GET_TITLE_BAR_INFO,
        GET_WINDOW_CONTEXT_HELP_ID, GET_WINDOW_DC, GET_WINDOW_DISPLAY_AFFINITY, GET_WINDOW_RGN_EX,
        INTERNAL_GET_WINDOW_TEXT, LOCK_WINDOW_UPDATE, PRINT_WINDOW, REAL_CHILD_WINDOW_FROM_POINT,
        SET_FOREGROUND_WINDOW, SET_INTERNAL_WINDOW_POS, SET_LAYERED_ATTRIBUTES, SET_PARENT,
        SET_PROGMAN_WINDOW, SET_SHELL_WINDOW_EX, SET_TASKMAN_WINDOW, SET_WINDOW_CONTEXT_HELP_ID,
        SET_WINDOW_RGN, SHOW_OWNED_POPUPS, SHOW_WINDOW_ASYNC, UPDATE_LAYERED_WINDOW, WINDOW_FROM_DC,
        WINDOW_FROM_POINT] {
        assert!(claims(ordinal), "{ordinal:#x}");
    }
    // The ordinals that belong to the message, paint and placement entries.
    assert!(!claims(0x15bd));
    assert!(!claims(0x1463));
    assert!(!claims(0));
}

#[test]
fn the_real_child_search_skips_the_transparent_and_hidden_children() {
    assert_eq!(real_child_flags(),
        ipc::win32_window::CWP_SKIPTRANSPARENT | ipc::win32_window::CWP_SKIPINVISIBLE);
    assert_eq!(real_child_flags() & ipc::win32_window::CWP_SKIPDISABLED, 0);
}

#[test]
fn a_record_of_any_other_size_than_this_build_knows_is_refused() {
    assert!(record_size_matches(FLASHWINFO_BYTES, FLASHWINFO_BYTES));
    assert!(!record_size_matches(FLASHWINFO_BYTES - 4, FLASHWINFO_BYTES));
    assert!(!record_size_matches(0, GUITHREADINFO_BYTES));
    assert!(record_size_matches(TITLEBARINFO_BYTES, TITLEBARINFO_BYTES));
}

#[test]
fn the_records_keep_their_field_order() {
    assert_eq!((FLASHWINFO_SIZE, FLASHWINFO_HWND, FLASHWINFO_FLAGS), (0, 8, 16));
    assert_eq!((GUITHREADINFO_SIZE, GUITHREADINFO_FLAGS, GUITHREADINFO_ACTIVE, GUITHREADINFO_FOCUS,
        GUITHREADINFO_CAPTURE, GUITHREADINFO_MENU_OWNER, GUITHREADINFO_MOVE_SIZE, GUITHREADINFO_CARET,
        GUITHREADINFO_CARET_RECT), (0, 4, 8, 16, 24, 32, 40, 48, 56));
    assert_eq!((TITLEBARINFO_SIZE, TITLEBARINFO_RECT, TITLEBARINFO_STATE), (0, 4, 20));
    assert_eq!(TITLEBARINFO_BYTES as usize,
        TITLEBARINFO_STATE as usize + ipc::win32_window::TITLE_BAR_ELEMENTS * 4);
    assert_eq!((PROPERTY_ENTRY_DATA, PROPERTY_ENTRY_ATOM, PROPERTY_ENTRY_STRING, PROPERTY_ENTRY_BYTES),
        (0, 8, 12, 16));
}

#[test]
fn a_flash_with_no_flags_stops_the_flashing_whatever_the_window_was_doing() {
    assert_eq!(flash_activates(0, true), Some(false));
    assert_eq!(flash_activates(0, false), Some(false));
}

#[test]
fn a_caption_flash_marks_an_inactive_window_active_and_leaves_an_active_one_alone() {
    assert_eq!(flash_activates(FLASHW_CAPTION, false), Some(true));
    assert_eq!(flash_activates(FLASHW_CAPTION, true), None);
}

#[test]
fn a_flash_without_the_caption_flag_changes_no_state() {
    assert_eq!(flash_activates(0x10, false), None);
}

#[test]
fn the_caret_flag_is_the_one_the_thread_information_record_carries() {
    assert_eq!(GUI_CARETBLINKING, 1);
}
