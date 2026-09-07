//! Logical palette object contract: creation, entry ranges, realization state.
use super::*;
use super::super::DEFAULT_PALETTE_HANDLE;

fn entry(red: u8, green: u8, blue: u8) -> PaletteEntry { PaletteEntry { red, green, blue, flags: 0 } }

fn palette_of(gdi: &mut GdiManager, count: usize) -> u32 {
    let entries: Vec<PaletteEntry> = (0..count).map(|index| entry(index as u8, 0, 0)).collect();
    gdi.create_palette(PALETTE_VERSION, &entries).unwrap()
}

#[test]
fn created_palette_keeps_its_version_entries_and_typed_identity() {
    let mut gdi = GdiManager::new();
    let handle = gdi.create_palette(0x300, &[entry(1, 2, 3), entry(4, 5, 6)]).unwrap();
    assert_eq!(handle & 0x00ff_0000, TYPE_PALETTE);
    assert_eq!(gdi.palette_count(handle), Some(2));
    assert_eq!(gdi.palette(handle).unwrap().version, 0x300);
    assert_eq!(gdi.palette(handle).unwrap().entries()[1], entry(4, 5, 6));
    assert!(gdi.contains_object(handle));
}

#[test]
fn default_palette_holds_the_twenty_static_system_colours() {
    assert_eq!(default_palette_entry(0), Some(entry(0x00, 0x00, 0x00)));
    assert_eq!(default_palette_entry(9), Some(entry(0xa6, 0xca, 0xf0)));
    // Entry ten continues in the colour table's last block, not the cube.
    assert_eq!(default_palette_entry(10), Some(entry(0xff, 0xfb, 0xf0)));
    assert_eq!(default_palette_entry(19), Some(entry(0xff, 0xff, 0xff)));
    assert_eq!(default_palette_entry(20), None);
    let gdi = GdiManager::new();
    assert_eq!(gdi.palette_count(DEFAULT_PALETTE_HANDLE), Some(DEFAULT_PALETTE_ENTRIES));
}

#[test]
fn halftone_palette_is_the_whole_eight_bit_default_table() {
    let mut gdi = GdiManager::new();
    let handle = gdi.create_halftone_palette().unwrap();
    assert_eq!(gdi.palette_count(handle), Some(HALFTONE_PALETTE_ENTRIES));
    assert_eq!(gdi.palette(handle).unwrap().entries()[10], entry(0x40, 0x20, 0x00));
    assert_eq!(gdi.palette(handle).unwrap().entries()[255], entry(0xff, 0xff, 0xff));
}

#[test]
fn zero_count_reports_the_entry_total_and_copies_nothing() {
    let mut gdi = GdiManager::new();
    let handle = palette_of(&mut gdi, 5);
    let mut out = [PaletteEntry::default(); 5];
    assert_eq!(gdi.get_palette_entries(handle, 0, 0, &mut out), 5);
    assert_eq!(out[0], PaletteEntry::default());
    assert_eq!(gdi.get_palette_entries(99, 0, 0, &mut out), 0);
}

#[test]
fn entry_range_shortens_at_the_end_and_a_start_past_the_end_copies_nothing() {
    let mut gdi = GdiManager::new();
    let handle = palette_of(&mut gdi, 5);
    let mut out = [PaletteEntry::default(); 5];
    assert_eq!(gdi.get_palette_entries(handle, 3, 4, &mut out), 2);
    assert_eq!(out[0], entry(3, 0, 0));
    assert_eq!(out[1], entry(4, 0, 0));
    assert_eq!(gdi.get_palette_entries(handle, 5, 1, &mut out), 0);
    assert_eq!(gdi.get_palette_entries(handle, 9, 1, &mut out), 0);
}

#[test]
fn setting_entries_shortens_refuses_the_stock_palette_and_unrealizes() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(4, 4).unwrap();
    let handle = palette_of(&mut gdi, 4);
    gdi.select_palette(dc, handle, false).unwrap();
    gdi.realize_palette(dc).unwrap();
    assert_eq!(gdi.set_palette_entries(handle, 2, 8, &[entry(9, 9, 9), entry(8, 8, 8)]), 2);
    let mut out = [PaletteEntry::default(); 2];
    assert_eq!(gdi.get_palette_entries(handle, 2, 2, &mut out), 2);
    assert_eq!(out, [entry(9, 9, 9), entry(8, 8, 8)]);
    assert_eq!(gdi.set_palette_entries(handle, 4, 1, &[entry(1, 1, 1)]), 0);
    assert_eq!(gdi.set_palette_entries(DEFAULT_PALETTE_HANDLE, 0, 1, &[entry(1, 1, 1)]), 0);
    // The write unrealized the palette, so the next realization is not skipped.
    assert_eq!(gdi.realize_palette(dc), Ok(0));
}

#[test]
fn animation_replaces_only_reserved_entries_and_accepts_the_stock_palette() {
    let mut gdi = GdiManager::new();
    let reserved = PaletteEntry { red: 1, green: 1, blue: 1, flags: PC_RESERVED };
    let handle = gdi.create_palette(PALETTE_VERSION, &[reserved, entry(2, 2, 2)]).unwrap();
    assert!(gdi.animate_palette(handle, 0, 2, &[entry(7, 7, 7), entry(8, 8, 8)]));
    let mut out = [PaletteEntry::default(); 2];
    gdi.get_palette_entries(handle, 0, 2, &mut out);
    assert_eq!(out[0], entry(7, 7, 7));
    assert_eq!(out[1], entry(2, 2, 2));
    assert!(gdi.animate_palette(DEFAULT_PALETTE_HANDLE, 0, 1, &[entry(1, 1, 1)]));
    assert!(!gdi.animate_palette(handle, 2, 1, &[entry(1, 1, 1)]));
    assert!(!gdi.animate_palette(99, 0, 1, &[entry(1, 1, 1)]));
}

#[test]
fn resize_zero_fills_growth_truncates_shrinkage_and_refuses_unknown_handles() {
    let mut gdi = GdiManager::new();
    let handle = palette_of(&mut gdi, 2);
    assert!(gdi.resize_palette(handle, 4));
    let mut out = [entry(9, 9, 9); 4];
    assert_eq!(gdi.get_palette_entries(handle, 0, 4, &mut out), 4);
    assert_eq!(out[3], PaletteEntry::default());
    assert!(gdi.resize_palette(handle, 1));
    assert_eq!(gdi.palette_count(handle), Some(1));
    assert!(!gdi.resize_palette(DEFAULT_PALETTE_HANDLE, 4));
    assert!(!gdi.resize_palette(99, 4));
}

#[test]
fn nearest_index_takes_the_least_squared_distance_and_stops_at_an_exact_match() {
    let mut gdi = GdiManager::new();
    let handle = gdi.create_palette(PALETTE_VERSION, &[entry(0, 0, 0), entry(0xff, 0, 0), entry(0xff, 0, 0)]).unwrap();
    // COLORREF orders red, green, blue from the low byte.
    assert_eq!(gdi.nearest_palette_index(handle, 0x0000_00f0), 1);
    assert_eq!(gdi.nearest_palette_index(handle, 0x0000_00ff), 1);
    assert_eq!(gdi.nearest_palette_index(handle, 0x0000_0000), 0);
    assert_eq!(gdi.nearest_palette_index(99, 0x0000_00ff), 0);
}

#[test]
fn nearest_colour_passes_through_on_a_direct_colour_device() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(2, 2).unwrap();
    assert_eq!(gdi.nearest_color(dc, 0x0201_0203, false), Ok(0x0201_0203));
    assert_eq!(gdi.nearest_color(99, 0, false), Err(GdiError::NoSuchObject));
}

#[test]
fn nearest_colour_resolves_palette_specs_on_a_palettised_device() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(2, 2).unwrap();
    let handle = gdi.create_palette(PALETTE_VERSION, &[entry(0x10, 0x20, 0x30), entry(0xff, 0, 0)]).unwrap();
    gdi.select_palette(dc, handle, false).unwrap();
    // A plain RGB colorref keeps its value, masked to the low three bytes.
    assert_eq!(gdi.nearest_color(dc, 0x0012_3456, true), Ok(0x0012_3456));
    // PALETTEINDEX names an entry; PALETTERGB asks for the nearest one.
    assert_eq!(gdi.nearest_color(dc, 0x0100_0000, true), Ok(0x0030_2010));
    assert_eq!(gdi.nearest_color(dc, 0x0100_0001, true), Ok(0x0000_00ff));
    assert_eq!(gdi.nearest_color(dc, 0x0200_00ff, true), Ok(0x0000_00ff));
    // An index past the end falls back to entry zero.
    assert_eq!(gdi.nearest_color(dc, 0x0100_0009, true), Ok(0x0030_2010));
}

#[test]
fn system_palette_use_refuses_a_device_without_a_palette_and_an_unnamed_selector() {
    let mut gdi = GdiManager::new();
    assert_eq!(gdi.system_palette_use(), SYSPAL_STATIC);
    assert_eq!(gdi.set_system_palette_use(SYSPAL_NOSTATIC, false), SYSPAL_ERROR);
    assert_eq!(gdi.system_palette_use(), SYSPAL_STATIC);
    assert_eq!(gdi.set_system_palette_use(SYSPAL_NOSTATIC, true), SYSPAL_STATIC);
    assert_eq!(gdi.system_palette_use(), SYSPAL_NOSTATIC);
    assert_eq!(gdi.set_system_palette_use(SYSPAL_NOSTATIC256, true), SYSPAL_NOSTATIC);
    assert_eq!(gdi.set_system_palette_use(9, true), SYSPAL_ERROR);
    assert_eq!(gdi.system_palette_use(), SYSPAL_NOSTATIC256);
}

#[test]
fn selection_returns_the_previous_palette_and_refuses_a_non_palette_handle() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(2, 2).unwrap();
    let brush = gdi.create_solid_brush(0).unwrap();
    let handle = palette_of(&mut gdi, 2);
    assert_eq!(gdi.dc_palette(dc), Ok(DEFAULT_PALETTE_HANDLE));
    assert_eq!(gdi.select_palette(dc, handle, false), Ok(DEFAULT_PALETTE_HANDLE));
    assert_eq!(gdi.dc_palette(dc), Ok(handle));
    assert_eq!(gdi.select_palette(dc, brush, false), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.select_palette(99, handle, false), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.primary_palette(), None);
    assert_eq!(gdi.select_palette(dc, DEFAULT_PALETTE_HANDLE, true), Ok(handle));
    assert_eq!(gdi.primary_palette(), Some(DEFAULT_PALETTE_HANDLE));
}

#[test]
fn realization_maps_nothing_on_a_direct_colour_device_and_is_skipped_when_repeated() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(2, 2).unwrap();
    let handle = palette_of(&mut gdi, 2);
    // The stock default palette realizes through a separate driver entry.
    assert_eq!(gdi.realize_palette(dc), Ok(0));
    gdi.select_palette(dc, handle, false).unwrap();
    assert_eq!(gdi.realize_palette(dc), Ok(0));
    assert_eq!(gdi.realize_palette(dc), Ok(0));
    assert!(gdi.unrealize_object(handle));
    assert_eq!(gdi.realize_palette(dc), Ok(0));
    assert_eq!(gdi.realize_palette(99), Err(GdiError::NoSuchObject));
    // Unrealizing an object with no realization state still reports success.
    assert!(gdi.unrealize_object(99));
}

#[test]
fn deleting_a_palette_clears_every_reference_the_owner_holds() {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(2, 2).unwrap();
    let handle = palette_of(&mut gdi, 2);
    gdi.select_palette(dc, handle, true).unwrap();
    gdi.realize_palette(dc).unwrap();
    assert_eq!(gdi.delete_object(handle), Ok(()));
    assert!(!gdi.contains_object(handle));
    assert_eq!(gdi.dc_palette(dc), Ok(DEFAULT_PALETTE_HANDLE));
    assert_eq!(gdi.primary_palette(), None);
    assert_eq!(gdi.delete_object(handle), Err(GdiError::NoSuchObject));
}
