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

/// A device that records the OP and FLAGS of every request handed to it.
///
/// Asserting on what a source stored proves only that it stored something.
/// The question this answers is the other one: what did the device actually
/// receive.
struct Spy {
    seen: sync::Spinlock<alloc::vec::Vec<(block::BlockOp, block::RequestFlags)>, sync::TaskList>,
    bytes: sync::Spinlock<alloc::vec::Vec<u8>, sync::TaskList>,
    block_size: u32,
}

impl Spy {
    fn new(block_size: u32, blocks: usize) -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            seen: sync::Spinlock::new(alloc::vec::Vec::new()),
            bytes: sync::Spinlock::new(alloc::vec![0u8; block_size as usize * blocks]),
            block_size,
        })
    }
    fn seen(&self) -> alloc::vec::Vec<(block::BlockOp, block::RequestFlags)> { self.seen.lock().clone() }
}

impl block::BlockDevice for Spy {
    fn block_size(&self) -> u32 { self.block_size }
    fn capacity_blocks(&self) -> u64 { self.bytes.lock().len() as u64 / u64::from(self.block_size) }
    fn flush(&self) -> block::KResult<()> { Ok(()) }
    fn submit_sync(&self, req: &mut block::BlockRequest) -> block::KResult<()> {
        self.seen.lock().push((req.op, req.flags));
        let bs = self.block_size as usize;
        let off = req.start_block as usize * bs;
        let len = req.len_blocks as usize * bs;
        let mut bytes = self.bytes.lock();
        match req.op {
            block::BlockOp::Read => req.buffer.copy_from_slice(&bytes[off..off + len]),
            block::BlockOp::Write => bytes[off..off + len].copy_from_slice(&req.buffer),
            _ => {}
        }
        Ok(())
    }
}

#[test]
fn a_hinted_write_reaches_the_device_carrying_its_hints() {
    let spy = Spy::new(SECTOR, 8);
    let src = BlockSource::new(spy.clone()).writable(true).with_sector_size(SECTOR);
    let hints = block::flags::PRIO | block::flags::META;
    src.write_sectors_flags(2, &[0x11; SECTOR as usize], hints).unwrap();
    // Not "the source remembers the hint" — the request the DEVICE was handed
    // carries it. Nothing between here and the queue may drop it.
    assert_eq!(spy.seen(), alloc::vec![(block::BlockOp::Write, hints)]);
    assert_eq!(spy.bytes.lock()[SECTOR as usize * 2], 0x11);
}

#[test]
fn a_plain_write_reaches_the_device_with_no_hints() {
    let spy = Spy::new(SECTOR, 8);
    let src = BlockSource::new(spy.clone()).writable(true).with_sector_size(SECTOR);
    src.write_sectors(2, &[0x22; SECTOR as usize]).unwrap();
    assert_eq!(spy.seen(), alloc::vec![(block::BlockOp::Write, block::RequestFlags::NONE)]);
}

#[test]
fn a_partial_block_write_hints_the_read_it_has_to_do_first() {
    // Device blocks are 4096 and the volume addresses 512, so this write
    // covers part of a block and must read it back first. That read is part
    // of the hinted write and must not queue as ordinary traffic.
    let spy = Spy::new(4096, 4);
    let src = BlockSource::new(spy.clone()).writable(true).with_sector_size(SECTOR);
    src.write_sectors_flags(1, &[0x33; SECTOR as usize], block::flags::PRIO).unwrap();
    assert_eq!(spy.seen(), alloc::vec![(block::BlockOp::Read, block::flags::PRIO),
                                       (block::BlockOp::Write, block::flags::PRIO)]);
}

#[test]
fn a_medium_with_no_queue_ignores_the_hints_and_writes_the_same_bytes() {
    // MemImage does not override the flagged entry point. The default must
    // still perform the write, because the flags are about order alone.
    let img = MemImage::new(SECTOR, 4);
    img.write_sectors_flags(1, &[0x5A; 16], block::flags::PRIO | block::flags::META).unwrap();
    assert_eq!(img.peek(SECTOR as usize, 16), alloc::vec![0x5A; 16]);
}

#[test]
fn a_read_only_source_refuses_a_hinted_write_at_the_same_place() {
    let spy = Spy::new(SECTOR, 8);
    let src = BlockSource::new(spy.clone()).with_sector_size(SECTOR);
    assert_eq!(src.write_sectors_flags(0, &[1u8; 4], block::flags::PRIO), Err(Errno::Erofs));
    // A refused write reaches no device at all — a hint does not open a path
    // around the read-only check.
    assert!(spy.seen().is_empty());
}
