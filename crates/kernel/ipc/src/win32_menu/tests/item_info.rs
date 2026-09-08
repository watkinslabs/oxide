//! The MENUITEMINFOW transaction as the menu-template loader issues it: an
//! append names its text by pointer alone and leaves the character count
//! zero, so a bar built from a resource keeps every label and measures every
//! item from it.
use super::*;
use crate::win32_gdi::menu_bar_metrics;
use crate::win32_menu::draw::MenuDrawOp;
use crate::win32_menu::{MenuItem, MenuManager, MenuRect, MF_BYPOSITION, MF_GRAYED, MF_SEPARATOR};
use alloc::vec;
use alloc::vec::Vec;

/// The five labels of the reference text editor's own menu bar.
const NOTEPAD_BAR: [&[u8]; 5] = [b"&File", b"&Edit", b"F&ormat", b"&View", b"&Help"];

/// Address the fixture's strings begin at, far from any real mapping.
const STRING_BASE: u64 = 0x1_0000;

/// One MENUITEMINFOW image plus the string memory its pointer names.
struct Fixture { image: [u8; MENUITEMINFO_BYTES], units: Vec<(u64, u16)> }

impl Fixture {
    /// Read one unit of the fixture's string memory, the way the kernel reads
    /// one unit of the caller's.
    fn unit(&self, address: u64) -> Option<u16> { self.units.iter().find(|(at, _)| *at == address).map(|(_, value)| *value) }
}

fn put_u32(image: &mut [u8; MENUITEMINFO_BYTES], offset: usize, value: u32) { image[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }
fn put_u64(image: &mut [u8; MENUITEMINFO_BYTES], offset: usize, value: u64) { image[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); }

/// The image an append of one string item produces: the mask names the state,
/// the identifier, the type and the string; the count stays zero.
fn append_image(id: u32, label: &[u8], flags: u32, count: u32) -> Fixture {
    let mut image = [0u8; MENUITEMINFO_BYTES];
    put_u32(&mut image, OFFSET_SIZE, MENUITEMINFO_BYTES as u32);
    put_u32(&mut image, OFFSET_MASK, MIIM_STATE | MIIM_ID | MIIM_FTYPE | MIIM_STRING | MIIM_BITMAP | MIIM_CHECKMARKS);
    put_u32(&mut image, OFFSET_TYPE, flags & MENUITEMINFO_TYPE_MASK);
    put_u32(&mut image, OFFSET_STATE, flags & MENUITEMINFO_STATE_MASK);
    put_u32(&mut image, OFFSET_ID, id);
    put_u64(&mut image, OFFSET_TEXT, STRING_BASE);
    put_u32(&mut image, OFFSET_COUNT, count);
    let mut units = Vec::new();
    for (index, byte) in label.iter().enumerate() { units.push((STRING_BASE + index as u64 * 2, *byte as u16)); }
    units.push((STRING_BASE + label.len() as u64 * 2, 0));
    Fixture { image, units }
}

fn wide(label: &[u8]) -> Vec<u16> { label.iter().map(|unit| *unit as u16).collect() }

#[test]
fn an_append_keeps_its_whole_label_although_the_character_count_is_zero() {
    let fixture = append_image(1, b"&File", 0, 0);
    let info = ItemInfo::decode(&fixture.image).unwrap();
    assert_eq!(info.count, 0);
    assert_eq!(info.read_text(|address| fixture.unit(address)), Ok(Some(wide(b"&File"))));
}

#[test]
fn a_character_count_shorter_than_the_string_does_not_truncate_a_set() {
    let fixture = append_image(1, b"F&ormat", 0, 2);
    let info = ItemInfo::decode(&fixture.image).unwrap();
    assert_eq!(info.read_text(|address| fixture.unit(address)), Ok(Some(wide(b"F&ormat"))));
}

#[test]
fn a_named_string_with_no_pointer_clears_the_item_text() {
    let mut fixture = append_image(1, b"&File", 0, 0);
    put_u64(&mut fixture.image, OFFSET_TEXT, 0);
    let info = ItemInfo::decode(&fixture.image).unwrap();
    assert_eq!(info.text_source(), TextSource::Cleared);
    assert_eq!(info.read_text(|address| fixture.unit(address)), Ok(Some(Vec::new())));
}

#[test]
fn an_unnamed_string_leaves_the_item_text_alone() {
    let mut fixture = append_image(1, b"&File", 0, 0);
    put_u32(&mut fixture.image, OFFSET_MASK, MIIM_ID);
    let info = ItemInfo::decode(&fixture.image).unwrap();
    assert_eq!(info.text_source(), TextSource::Untouched);
    assert_eq!(info.read_text(|address| fixture.unit(address)), Ok(None));
}

#[test]
fn a_string_that_faults_reports_the_fault_rather_than_a_short_label() {
    let fixture = append_image(1, b"&File", 0, 0);
    let info = ItemInfo::decode(&fixture.image).unwrap();
    assert_eq!(info.read_text(|address| if address == STRING_BASE { Some(b'&' as u16) } else { None }), Err(ItemInfoError::Fault));
}

#[test]
fn the_type_word_and_the_state_word_land_in_one_flag_set() {
    let separator = append_image(0, b"", MF_SEPARATOR | MF_GRAYED, 0);
    let info = ItemInfo::decode(&separator.image).unwrap();
    assert_eq!(info.type_value(), Some(MF_SEPARATOR));
    assert_eq!(info.state_value(), Some(MF_GRAYED));
    assert_eq!(info.insert_flags(), MF_SEPARATOR | MF_GRAYED);
}

#[test]
fn the_selectors_that_do_not_describe_an_item_never_reach_its_flags() {
    let fixture = append_image(1, b"&File", MF_BYPOSITION, 0);
    let info = ItemInfo::decode(&fixture.image).unwrap();
    assert_eq!(info.insert_flags() & MF_BYPOSITION, 0);
}

#[test]
fn an_image_of_another_size_is_refused() {
    let mut fixture = append_image(1, b"&File", 0, 0);
    put_u32(&mut fixture.image, OFFSET_SIZE, MENUITEMINFO_BYTES as u32 - 8);
    assert_eq!(ItemInfo::decode(&fixture.image), None);
}

#[test]
fn a_query_leaves_one_unit_of_the_buffer_for_the_terminator() {
    assert_eq!(query_text_units(5, 0, false), 5);
    assert_eq!(query_text_units(5, 3, true), 2);
    assert_eq!(query_text_units(5, 6, true), 5);
    assert_eq!(query_text_units(5, 20, true), 5);
}

/// The whole path a resource-loaded bar takes: five appends, then the plan
/// the nonclient painter walks.
#[test]
fn a_bar_appended_from_a_template_draws_one_text_run_per_item() {
    let mut menus = MenuManager::new();
    let menu = menus.create().unwrap();
    for (position, label) in NOTEPAD_BAR.iter().enumerate() {
        let fixture = append_image(position as u32 + 1, label, 0, 0);
        let info = ItemInfo::decode(&fixture.image).unwrap();
        let text = info.read_text(|address| fixture.unit(address)).unwrap().unwrap();
        menus.insert(menu, position, MenuItem { id: info.id, state: info.insert_flags(), text, submenu: info.submenu }).unwrap();
    }
    let origin = MenuRect { left: 0, top: 0, right: 582 - 261, bottom: 768 - 122 };
    let cells = menu_bar_metrics();
    let plan = menus.bar_draw_plan(menu, origin, &cells).unwrap();
    let runs: Vec<(u32, MenuRect)> = plan.iter().filter_map(|op| match op { MenuDrawOp::Text { rect, position, .. } => Some((*position, *rect)), _ => None }).collect();
    assert_eq!(runs.len(), NOTEPAD_BAR.len());
    for (position, label) in NOTEPAD_BAR.iter().enumerate() {
        let item = menus.item(menu, position as u32, MF_BYPOSITION).unwrap();
        assert_eq!(item.text, wide(label));
        let cell = menus.bar_item_rect(menu, position, origin, &cells).unwrap();
        // The cell is measured from the label as it is drawn, so the prefix
        // that marks the mnemonic costs no column, and the run sits inside it.
        let drawn = crate::win32_menu::mnemonic::display_text(&item.text);
        assert_eq!(drawn.units.len(), label.len() - 1, "one prefix per label is consumed");
        assert_eq!(cell.right - cell.left, cells.cells.extent(&drawn.units) + 2 * cells.char_width);
        assert_eq!(runs[position], (position as u32, MenuRect { left: cell.left + cells.char_width, top: cell.top, right: cell.right - cells.char_width, bottom: cell.bottom }));
    }
    let bar = menus.bar_rect(menu, origin, &cells).unwrap();
    assert!(bar.bottom - bar.top > 0);
    assert_eq!(bar.right, runs[NOTEPAD_BAR.len() - 1].1.right + cells.char_width);
}

/// A separator carries its bit in the type word, so a bar skips it and a
/// template that ends a popup with one still draws every real item.
#[test]
fn a_separator_from_a_template_draws_no_run_on_a_bar() {
    let mut menus = MenuManager::new();
    let menu = menus.create().unwrap();
    let items: [(&[u8], u32); 2] = [(b"&File", 0), (b"", MF_SEPARATOR | MF_GRAYED)];
    for (position, (label, flags)) in items.iter().enumerate() {
        let fixture = append_image(position as u32 + 1, label, *flags, 0);
        let info = ItemInfo::decode(&fixture.image).unwrap();
        let text = info.read_text(|address| fixture.unit(address)).unwrap().unwrap();
        menus.insert(menu, position, MenuItem { id: info.id, state: info.insert_flags(), text, submenu: info.submenu }).unwrap();
    }
    let origin = MenuRect { left: 0, top: 0, right: 320, bottom: 240 };
    let cells = menu_bar_metrics();
    let plan = menus.bar_draw_plan(menu, origin, &cells).unwrap();
    let runs = plan.iter().filter(|op| matches!(op, MenuDrawOp::Text { .. })).count();
    assert_eq!(runs, 1);
    assert_eq!(vec![menus.item(menu, 1, MF_BYPOSITION).unwrap().state & MF_SEPARATOR], vec![MF_SEPARATOR]);
}

/// A write of an item's state replaces the whole state side of its flag word
/// and leaves the type side standing, the way the reference assigns one and
/// masks the other.
#[test]
fn a_state_write_replaces_the_state_side_and_keeps_the_type_side() {
    use crate::win32_menu::{MF_CHECKED, MF_POPUP};
    let mut menus = MenuManager::new();
    let menu = menus.create().unwrap();
    menus.insert(menu, 0, MenuItem { id: 1, state: MF_SEPARATOR | MF_POPUP | MF_CHECKED, text: wide(b"&File"), submenu: None }).unwrap();
    menus.set_item(menu, 0, None, None, Some(MF_GRAYED), None, None).unwrap();
    let item = menus.item(menu, 0, MF_BYPOSITION).unwrap();
    assert_eq!(item.state, MF_SEPARATOR | MF_POPUP | MF_GRAYED, "the checked bit goes, the type bits stay");
    menus.set_item(menu, 0, None, Some(0), None, None, None).unwrap();
    // The type write clears the type side it owns and leaves the popup and
    // system bits, which no MENUITEMINFOW type word carries.
    assert_eq!(menus.item(menu, 0, MF_BYPOSITION).unwrap().state, MF_POPUP | MF_GRAYED);
}
