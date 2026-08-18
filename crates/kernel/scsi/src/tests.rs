//! Hosted contracts for common SCSI LUN scanning and block translation.

extern crate alloc;

use alloc::sync::Arc;
use block::{BlockDevice, BlockError, BlockRequest, KResult};
use core::sync::atomic::{AtomicUsize, Ordering};
use sync::TaskList;

use crate::{BlockTransport, Command, CommandCompletion, DataDirection, Disk, Lun, Transport, READ_CAPACITY_10, READ_CAPACITY_16,
    SERVICE_ACTION_IN_16, scan_lun};

struct MultiLunFixture;

impl Transport for MultiLunFixture {
    fn max_lun(&self) -> Lun { Lun::new(1) }

    fn execute(&self, lun: Lun, command: &Command, data: &mut [u8], direction: DataDirection) -> KResult<CommandCompletion> {
        if direction != DataDirection::FromDevice { return Err(BlockError::Einval); }
        match (lun.value(), command.opcode()) {
            (0, 0x12) => { data.fill(0); data[1] = 0x80; Ok(CommandCompletion::good()) }
            (1, 0x12) => { data.fill(0); data[0] = 0x1f; Ok(CommandCompletion::good()) }
            (0, READ_CAPACITY_10) => {
                data.fill(0); data[..4].copy_from_slice(&u32::MAX.to_be_bytes()); data[4..8].copy_from_slice(&512u32.to_be_bytes()); Ok(CommandCompletion::good())
            }
            (0, SERVICE_ACTION_IN_16) if command.bytes().get(1) == Some(&READ_CAPACITY_16) => {
                data.fill(0); data[..8].copy_from_slice(&9u64.to_be_bytes()); data[8..12].copy_from_slice(&4096u32.to_be_bytes()); Ok(CommandCompletion::good())
            }
            _ => Err(BlockError::Eio),
        }
    }
}

#[test]
fn lun_scan_uses_capacity_16_after_the_10_byte_sentinel() {
    let found = scan_lun(&MultiLunFixture, Lun::ZERO).expect("scan").expect("disk");
    assert_eq!(found.lun(), Lun::ZERO);
    assert!(found.removable());
    assert_eq!(found.block_size(), 4096);
    assert_eq!(found.capacity(), 10);
}

#[test]
fn no_lun_inquiry_is_not_a_transport_failure() {
    assert_eq!(scan_lun(&MultiLunFixture, Lun::new(1)).expect("scan"), None);
}

#[test]
fn shared_disk_translates_read_write_and_flush() {
    let backing: Arc<dyn BlockDevice> = block::MemDisk::<TaskList>::new(512, 32);
    let disk = Disk::new(BlockTransport::new(backing), Lun::ZERO, 512, 32).expect("disk");
    let mut write = BlockRequest::new_write(3, 2, alloc::vec![0x5a; 1024]);
    disk.submit_sync(&mut write).expect("write");
    let mut read = BlockRequest::new_read(3, 2, 512);
    disk.submit_sync(&mut read).expect("read");
    assert_eq!(read.buffer, alloc::vec![0x5a; 1024]);
    disk.flush().expect("flush");
}

#[test]
fn block_transport_reports_capacity_16() {
    let backing: Arc<dyn BlockDevice> = block::MemDisk::<TaskList>::new(4096, 11);
    let transport = BlockTransport::new(backing);
    let command = Command::new(&[SERVICE_ACTION_IN_16, READ_CAPACITY_16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).expect("capacity");
    let mut data = [0u8; 32];
    transport.execute(Lun::ZERO, &command, &mut data, DataDirection::FromDevice).expect("capacity");
    assert_eq!(u64::from_be_bytes(data[..8].try_into().expect("last lba")), 10);
    assert_eq!(u32::from_be_bytes(data[8..12].try_into().expect("block size")), 4096);
}

struct BecomingReadyFixture { attempts: AtomicUsize, retry_delay_ms: AtomicUsize }

impl BecomingReadyFixture {
    const fn new() -> Self { Self { attempts: AtomicUsize::new(0), retry_delay_ms: AtomicUsize::new(0) } }
}

impl Transport for BecomingReadyFixture {
    fn execute(&self, _lun: Lun, command: &Command, data: &mut [u8], direction: DataDirection) -> KResult<CommandCompletion> {
        if command.opcode() != crate::READ_10 || direction != DataDirection::FromDevice { return Err(BlockError::Einval); }
        if self.attempts.fetch_add(1, Ordering::AcqRel) == 0 {
            return Ok(CommandCompletion::check_condition(0, &[0x72, 0x02, 0x04, 0x01]));
        }
        data.fill(0x5a);
        Ok(CommandCompletion::good())
    }

    fn retry_delay(&self, delay_ms: u32) -> KResult<()> {
        self.retry_delay_ms.store(delay_ms as usize, Ordering::Release);
        Ok(())
    }
}

#[test]
fn block_io_reissues_a_becoming_ready_command_only_after_the_host_waits() {
    let transport = Arc::new(BecomingReadyFixture::new());
    let disk = Disk::new(transport.clone(), Lun::ZERO, 512, 4).expect("disk");
    let mut read = BlockRequest::new_read(0, 1, 512);
    disk.submit_sync(&mut read).expect("retried read");
    assert_eq!(transport.attempts.load(Ordering::Acquire), 2);
    assert_eq!(transport.retry_delay_ms.load(Ordering::Acquire), crate::QUEUE_RETRY_DELAY_MS as usize);
    assert_eq!(read.buffer, alloc::vec![0x5a; 512]);
}

struct NeverReadyFixture { attempts: AtomicUsize, waits: AtomicUsize }

impl NeverReadyFixture {
    const fn new() -> Self { Self { attempts: AtomicUsize::new(0), waits: AtomicUsize::new(0) } }
}

impl Transport for NeverReadyFixture {
    fn execute(&self, _lun: Lun, command: &Command, _data: &mut [u8], direction: DataDirection) -> KResult<CommandCompletion> {
        if command.opcode() != crate::READ_10 || direction != DataDirection::FromDevice { return Err(BlockError::Einval); }
        self.attempts.fetch_add(1, Ordering::AcqRel);
        Ok(CommandCompletion::check_condition(0, &[0x72, 0x02, 0x04, 0x01]))
    }

    fn retry_delay(&self, _delay_ms: u32) -> KResult<()> {
        self.waits.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

#[test]
fn block_retry_count_is_bounded_by_the_sd_default() {
    let transport = Arc::new(NeverReadyFixture::new());
    let disk = Disk::new(transport.clone(), Lun::ZERO, 512, 4).expect("disk");
    let mut read = BlockRequest::new_read(0, 1, 512);
    assert_eq!(disk.submit_sync(&mut read), Err(BlockError::Eio));
    assert_eq!(transport.attempts.load(Ordering::Acquire), usize::from(crate::DEFAULT_RETRIES) + 1);
    assert_eq!(transport.waits.load(Ordering::Acquire), usize::from(crate::DEFAULT_RETRIES));
}
