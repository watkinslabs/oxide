use super::*;
use syscall::errno::Errno;

const SECTOR: u32 = 512;

#[test]
fn read_returns_the_bytes_at_that_sector() {
    let img = MemImage::new(SECTOR, 8);
    img.poke(SECTOR as usize * 3, &[0xAB; 4]);
    let mut buf = [0u8; 4];
    img.read_sectors(3, &mut buf).unwrap();
    assert_eq!(buf, [0xAB; 4]);
}

#[test]
fn a_read_past_the_end_is_eio_not_a_short_read() {
    let img = MemImage::new(SECTOR, 2);
    let mut buf = [0u8; 8];
    assert_eq!(img.read_sectors(2, &mut buf), Err(Errno::Eio));
}

#[test]
fn a_write_lands_where_the_read_finds_it() {
    let img = MemImage::new(SECTOR, 4);
    img.write_sectors(1, &[0x5A; 16]).unwrap();
    assert_eq!(img.peek(SECTOR as usize, 16), alloc::vec![0x5A; 16]);
}

#[test]
fn a_read_only_image_refuses_writes() {
    let img = MemImage::new(SECTOR, 4).read_only();
    assert!(!img.writable());
    assert_eq!(img.write_sectors(0, &[1u8; 4]), Err(Errno::Erofs));
}

#[test]
fn a_write_past_the_end_changes_nothing() {
    let img = MemImage::new(SECTOR, 2);
    assert_eq!(img.write_sectors(1, &[9u8; 1024]), Err(Errno::Eio));
    assert!(img.snapshot().iter().all(|b| *b == 0));
}

#[test]
fn a_larger_sector_size_scales_the_offset() {
    let img = MemImage::new(4096, 2);
    img.write_sectors(1, &[7u8; 8]).unwrap();
    assert_eq!(img.peek(4096, 8), alloc::vec![7u8; 8]);
}
