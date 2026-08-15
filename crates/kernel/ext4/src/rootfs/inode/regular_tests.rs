use super::{HoleOrData, seek_in_runs};
use vfs::VfsError;

const BS: u64 = 4096;

#[test]
fn full_file_data_and_hole() {
    let runs = [(0u32, 10u32)];
    let size = 40000u64;
    assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Data), Ok(0));
    assert_eq!(seek_in_runs(&runs, BS, size, 5000, HoleOrData::Data), Ok(5000));
    assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Hole), Ok(size));
}

#[test]
fn sparse_middle_hole() {
    let runs = [(0u32, 1u32), (5u32, 3u32)];
    let size = 8 * BS;
    assert_eq!(seek_in_runs(&runs, BS, size, 100, HoleOrData::Hole), Ok(BS));
    assert_eq!(seek_in_runs(&runs, BS, size, 2 * BS, HoleOrData::Data), Ok(5 * BS));
    let off = 2 * BS + 17;
    assert_eq!(seek_in_runs(&runs, BS, size, off, HoleOrData::Hole), Ok(off));
    assert_eq!(seek_in_runs(&runs, BS, size, 6 * BS, HoleOrData::Hole), Ok(size));
}

#[test]
fn leading_hole() {
    let runs = [(3u32, 2u32)];
    let size = 6 * BS;
    assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Data), Ok(3 * BS));
    assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Hole), Ok(0));
}

#[test]
fn adjacent_runs_merge() {
    let runs = [(0u32, 2u32), (2u32, 1u32), (10u32, 1u32)];
    let size = 11 * BS;
    assert_eq!(seek_in_runs(&runs, BS, size, BS, HoleOrData::Hole), Ok(3 * BS));
    assert_eq!(seek_in_runs(&runs, BS, size, 5 * BS, HoleOrData::Data), Ok(10 * BS));
}

#[test]
fn no_more_data_enxio() {
    let runs = [(0u32, 1u32)];
    let size = 8 * BS;
    assert_eq!(seek_in_runs(&runs, BS, size, 4 * BS, HoleOrData::Data), Err(VfsError::Enxio));
}

#[test]
fn no_extents_all_hole() {
    let runs: [(u32, u32); 0] = [];
    let size = 3 * BS;
    assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Hole), Ok(0));
    assert_eq!(seek_in_runs(&runs, BS, size, BS, HoleOrData::Data), Err(VfsError::Enxio));
}
