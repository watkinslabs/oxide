//! Advances, the extent they sum to, and the character size a face reports.
use super::*;

/// One sub-pixel advance per character of the printable block.
fn table(advance: impl Fn(u16) -> u16) -> MenuCells {
    let mut words = [0u8; CELL_TABLE_BYTES];
    for index in 0..CELL_COUNT {
        let unit = CELL_FIRST + index as u16;
        words[index * 2..index * 2 + 2].copy_from_slice(&advance(unit).to_le_bytes());
    }
    MenuCells::from_words(&words, 16).unwrap()
}

#[test]
fn an_unmeasured_face_answers_its_average_advance_for_every_character() {
    let cells = MenuCells::uniform(5, 11);
    assert_eq!(cells.extent(&[b'i' as u16, b'W' as u16]), 10);
    assert_eq!(cells.char_size(), (5, 11));
}

#[test]
fn a_run_is_measured_by_its_own_glyphs_not_by_a_character_count() {
    // A narrow character and a wide one, so a count times an average cannot
    // reproduce either run.
    let cells = table(|unit| if unit == b'i' as u16 { 3 * CELL_SCALE as u16 } else { 9 * CELL_SCALE as u16 });
    assert_eq!(cells.extent(&[b'i' as u16; 4]), 12);
    assert_eq!(cells.extent(&[b'W' as u16; 4]), 36);
    assert_ne!(cells.extent(&[b'i' as u16; 4]), cells.extent(&[b'W' as u16; 4]));
}

#[test]
fn sub_pixel_advances_sum_before_they_round_once() {
    // Half a pixel each: eight of them are four pixels, not eight.
    let cells = table(|_| CELL_SCALE as u16 / 2);
    assert_eq!(cells.extent(&[b'a' as u16; 8]), 4);
    assert_eq!(cells.extent(&[b'a' as u16; 1]), 1);
}

#[test]
fn the_character_size_is_the_fifty_two_letter_sample_the_reference_quotes() {
    // Every letter six pixels: the sample is 312 wide, and the quoted size is
    // (312 / 26 + 1) / 2 = 6.
    let cells = table(|_| 6 * CELL_SCALE as u16);
    assert_eq!(cells.char_size(), (6, 16));
    // Ten pixels each gives (520 / 26 + 1) / 2 = 10.
    let cells = table(|_| 10 * CELL_SCALE as u16);
    assert_eq!(cells.char_size().0, 10);
}

#[test]
fn a_character_outside_the_measured_block_takes_the_block_mean() {
    let cells = table(|_| 4 * CELL_SCALE as u16);
    assert_eq!(cells.advance(0x4e00), 4 * CELL_SCALE as u16);
    assert_eq!(cells.extent(&[0x4e00, 0x4e01]), 8);
}

#[test]
fn a_table_of_the_wrong_length_is_refused() {
    assert_eq!(MenuCells::from_words(&[0u8; CELL_TABLE_BYTES - 2], 16), None);
    assert_eq!(MenuCells::from_words(&[0u8; CELL_TABLE_BYTES + 2], 16), None);
}
