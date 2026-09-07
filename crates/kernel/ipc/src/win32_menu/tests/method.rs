use super::*;

/// The method word each named transaction travels as. A call that reaches the
/// wrong slot answers a different question in a different currency — the
/// defect this table exists to prevent — so every number here is stated
/// literally rather than derived from the enum it pins.
const SLOTS: [(u64, MenuItemMethod); 9] = [
    (0, MenuItemMethod::SetMenuItemInfo),
    (1, MenuItemMethod::InsertMenuItem),
    (2, MenuItemMethod::CheckMenuRadioItem),
    (3, MenuItemMethod::GetMenuDefaultItem),
    (4, MenuItemMethod::GetMenuItemId),
    (5, MenuItemMethod::GetMenuItemInfoA),
    (6, MenuItemMethod::GetMenuItemInfoW),
    (7, MenuItemMethod::GetMenuState),
    (8, MenuItemMethod::GetSubMenu),
];

#[test]
fn every_method_word_decodes_to_the_transaction_that_sends_it() {
    for (raw, method) in SLOTS {
        assert_eq!(MenuItemMethod::from_raw(raw), Some(method), "method word {raw}");
        assert_eq!(method.raw(), raw);
    }
    assert_eq!(MenuItemMethod::from_raw(9), None);
    assert_eq!(MenuItemMethod::from_raw(u64::MAX), None);
}

#[test]
fn the_identifier_query_and_the_ansi_field_query_are_different_slots() {
    assert_eq!(MenuItemMethod::from_raw(4), Some(MenuItemMethod::GetMenuItemId));
    assert_eq!(MenuItemMethod::from_raw(5), Some(MenuItemMethod::GetMenuItemInfoA));
    assert!(!MenuItemMethod::GetMenuItemId.reads_item_block());
    assert!(MenuItemMethod::GetMenuItemInfoA.reads_item_block());
    assert!(MenuItemMethod::GetMenuItemInfoA.is_ansi_query());
    assert!(!MenuItemMethod::GetMenuItemInfoW.is_ansi_query());
}

#[test]
fn the_radio_range_call_never_reads_the_block_as_fields() {
    // Its caller fills only the count and mask words and leaves the size word
    // uninitialised, so a size check on that block would reject every call.
    assert!(!MenuItemMethod::CheckMenuRadioItem.reads_item_block());
    assert!(!MenuItemMethod::GetMenuDefaultItem.reads_item_block());
    assert!(!MenuItemMethod::GetMenuState.reads_item_block());
    assert!(!MenuItemMethod::GetSubMenu.reads_item_block());
}

#[test]
fn each_slot_reports_a_miss_in_its_own_currency() {
    assert_eq!(MenuItemMethod::GetMenuItemId.miss_value(), u32::MAX as u64);
    assert_eq!(MenuItemMethod::GetMenuState.miss_value(), u32::MAX as u64);
    assert_eq!(MenuItemMethod::GetMenuDefaultItem.miss_value(), u32::MAX as u64);
    assert_eq!(MenuItemMethod::GetSubMenu.miss_value(), 0);
    assert_eq!(MenuItemMethod::SetMenuItemInfo.miss_value(), 0);
    assert_eq!(MenuItemMethod::InsertMenuItem.miss_value(), 0);
    assert_eq!(MenuItemMethod::CheckMenuRadioItem.miss_value(), 0);
    assert_eq!(MenuItemMethod::GetMenuItemInfoA.miss_value(), 0);
    assert_eq!(MenuItemMethod::GetMenuItemInfoW.miss_value(), 0);
}

#[test]
fn a_popup_item_has_no_identifier_to_answer() {
    assert_eq!(item_id_result(Some(9), 7), u32::MAX);
    assert_eq!(item_id_result(None, 7), 7);
}

#[test]
fn a_popup_items_state_carries_its_submenu_size_above_its_flag_byte() {
    assert_eq!(item_state_result(0x0000_0083, None), 0x0000_0083);
    assert_eq!(item_state_result(0x0000_0183, Some(Some(3))), (3 << 8) | 0x83);
    assert_eq!(item_state_result(0x0000_0010, Some(None)), u32::MAX);
}

#[test]
fn the_default_item_search_flags_are_the_two_the_query_defines() {
    assert_eq!(GMDI_USEDISABLED, 0x0001);
    assert_eq!(GMDI_GOINTOPOPUPS, 0x0002);
}
