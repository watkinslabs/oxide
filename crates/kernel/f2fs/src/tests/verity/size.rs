//! The size rule: where the data stops and the metadata starts.

use crate::verity::location::{self, Location};
use crate::verity::uapi::*;
use crate::verity::VerityError;

use super::image;

const MAX_FILE: u64 = 1 << 40;

#[test]
fn the_metadata_starts_at_the_next_boundary_above_the_data() {
    assert_eq!(location::metadata_pos(0), 0);
    assert_eq!(location::metadata_pos(1), METADATA_ALIGN);
    assert_eq!(location::metadata_pos(METADATA_ALIGN - 1), METADATA_ALIGN);
    assert_eq!(location::metadata_pos(METADATA_ALIGN), METADATA_ALIGN);
    assert_eq!(location::metadata_pos(METADATA_ALIGN + 1), 2 * METADATA_ALIGN);
    // The boundary is not the block size: a file of one block still leaves
    // the rest of the alignment as a hole.
    assert_eq!(location::metadata_pos(4096), METADATA_ALIGN);
    assert!(METADATA_ALIGN > crate::uapi::BLKSIZE as u64);
}

#[test]
fn a_read_of_a_verity_file_stops_at_its_data() {
    let size = 5000;
    // The whole file: only the data comes back, never the tree behind it.
    assert_eq!(location::readable(size, 0, METADATA_ALIGN * 4), size);
    assert_eq!(location::readable(size, 4000, 4000), 1000);
    assert_eq!(location::readable(size, size, 4096), 0);
    assert_eq!(location::readable(size, size + 1, 4096), 0);
    // A read wholly inside the data is not shortened.
    assert_eq!(location::readable(size, 0, 100), 100);
    assert_eq!(location::readable(size, 4999, 1), 1);
}

#[test]
fn the_metadata_is_never_inside_the_data() {
    let size = 5000;
    assert!(location::is_data(size, 0, size));
    assert!(!location::is_data(size, 0, size + 1));
    assert!(!location::is_data(size, location::metadata_pos(size), 1));
    // A range that wraps is not data either.
    assert!(!location::is_data(size, u64::MAX, 2));
}

#[test]
fn the_attribute_holds_a_pointer_and_round_trips() {
    let pos = METADATA_ALIGN + 8192;
    let bytes = image::location(LOCATION_VERSION, 300, pos);
    let loc = location::parse(&bytes).expect("well formed");
    assert_eq!(loc.version, LOCATION_VERSION);
    assert_eq!(loc.size, 300);
    assert_eq!(loc.pos, pos);
    assert_eq!(&location::encode(&loc)[..], &bytes[..]);
    assert_eq!(bytes.len(), LOCATION_SIZE);
}

#[test]
fn a_pointer_of_another_version_or_width_is_a_format_this_build_does_not_know() {
    assert_eq!(
        location::parse(&image::location(LOCATION_VERSION + 1, 300, METADATA_ALIGN)),
        Err(VerityError::UnknownFormat)
    );
    let short = image::location(LOCATION_VERSION, 300, METADATA_ALIGN);
    assert_eq!(location::parse(&short[..LOCATION_SIZE - 1]), Err(VerityError::UnknownFormat));
    let mut long = short.clone();
    long.push(0);
    assert_eq!(location::parse(&long), Err(VerityError::UnknownFormat));
    assert_eq!(location::parse(&[]), Err(VerityError::UnknownFormat));
}

#[test]
fn a_descriptor_claimed_inside_the_data_is_refused() {
    // This is the attack the lower bound exists for: a descriptor placed
    // among the bytes it is supposed to attest to.
    let size = 200_000;
    let inside = Location { version: LOCATION_VERSION, size: 300, pos: size - 1 };
    assert_eq!(location::check(&inside, size, MAX_FILE), Err(VerityError::Corrupted));
    let boundary =
        Location { version: LOCATION_VERSION, size: 300, pos: location::metadata_pos(size) };
    assert_eq!(location::check(&boundary, size, MAX_FILE), Ok(()));
    let below = Location { pos: location::metadata_pos(size) - 1, ..boundary };
    assert_eq!(location::check(&below, size, MAX_FILE), Err(VerityError::Corrupted));
}

#[test]
fn a_descriptor_past_the_file_or_wrapping_past_it_is_refused() {
    let size = 200_000;
    let past = Location { version: LOCATION_VERSION, size: 300, pos: MAX_FILE };
    assert_eq!(location::check(&past, size, MAX_FILE), Err(VerityError::Corrupted));
    let wrap = Location { version: LOCATION_VERSION, size: u32::MAX, pos: u64::MAX };
    assert_eq!(location::check(&wrap, size, MAX_FILE), Err(VerityError::Corrupted));
    let last = Location { version: LOCATION_VERSION, size: 300, pos: MAX_FILE - 300 };
    assert_eq!(location::check(&last, size, MAX_FILE), Ok(()));
}

#[test]
fn a_descriptor_shorter_or_wider_than_the_format_admits_is_refused() {
    let size = 200_000;
    let at = location::metadata_pos(size);
    let small =
        Location { version: LOCATION_VERSION, size: DESCRIPTOR_SIZE as u32 - 1, pos: at };
    assert_eq!(location::check(&small, size, MAX_FILE), Err(VerityError::TruncatedDescriptor));
    let huge =
        Location { version: LOCATION_VERSION, size: MAX_DESCRIPTOR_SIZE as u32 + 1, pos: at };
    assert_eq!(location::check(&huge, size, MAX_FILE), Err(VerityError::DescriptorTooLarge));
    let exact = Location { version: LOCATION_VERSION, size: DESCRIPTOR_SIZE as u32, pos: at };
    assert_eq!(location::check(&exact, size, MAX_FILE), Ok(()));
}
