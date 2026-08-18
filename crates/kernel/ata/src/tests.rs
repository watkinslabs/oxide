//! Hosted ATA ABI and SAT translation contracts.

extern crate alloc;

use alloc::sync::Arc;

use crate::{Device, IDENTIFY_BYTES, Taskfile, TaskfileResult};

fn write_ata_string(page: &mut [u8; 512], offset: usize, text: &[u8]) {
    assert_eq!(text.len() % 2, 0);
    for (index, pair) in text.chunks_exact(2).enumerate() {
        page[offset + index * 2] = pair[1];
        page[offset + index * 2 + 1] = pair[0];
    }
}

#[test]
fn hdio_identity_swaps_only_the_ata_string_fields() {
    let mut page = [0xa5; 512];
    write_ata_string(&mut page, 20, b"SN-42               ");
    write_ata_string(&mut page, 46, b"FW1.0   ");
    write_ata_string(&mut page, 54, b"Oxide ATA disk                          ");
    let raw = page;

    crate::identity::normalize_identity(&mut page);

    assert_eq!(&page[..20], &raw[..20]);
    assert_eq!(&page[20..40], b"SN-42               ");
    assert_eq!(&page[40..46], &raw[40..46]);
    assert_eq!(&page[46..54], b"FW1.0   ");
    assert_eq!(&page[54..94], b"Oxide ATA disk                          ");
    assert_eq!(&page[94..], &raw[94..]);
}

struct Fixture { page: [u8; IDENTIFY_BYTES] }

impl Device for Fixture {
    fn identify_page(&self) -> Option<[u8; IDENTIFY_BYTES]> { Some(self.page) }
    fn execute_taskfile(&self, _taskfile: Taskfile, _data: &mut [u8], _timeout_ms: u32)
        -> block::KResult<TaskfileResult>
    {
        unreachable!("identity fixture never executes a taskfile")
    }
    fn max_transfer_bytes(&self) -> usize { 0 }
}

#[test]
fn published_dev_t_owns_one_live_ata_identity_source() {
    const DEV_T: u32 = 0x0008_00f0;
    let _ = crate::unregister_target(DEV_T);
    let mut page = [0u8; IDENTIFY_BYTES];
    write_ata_string(&mut page, crate::identity::TEST_SERIAL_OFFSET, b"ATA-IDENTITY-0001   ");
    let device: Arc<dyn Device> = Arc::new(Fixture { page });

    assert!(crate::register_target(DEV_T, device));
    let target = crate::identity_target(DEV_T).expect("registered ATA target");
    assert_eq!(&target.hdio_identity().expect("live page")[20..40], b"ATA-IDENTITY-0001   ");
    assert!(crate::unregister_target(DEV_T));
    assert!(crate::identity_target(DEV_T).is_none());
}

fn result(status: u8) -> TaskfileResult {
    TaskfileResult {
        extend: false, error: 0, nsect: 0x7f, lbal: 0, lbam: 0, lbah: 0,
        device: 0x40, status, hob_nsect: 0, hob_lbal: 0, hob_lbam: 0, hob_lbah: 0,
    }
}

struct TaskFixture { result: TaskfileResult }

impl Device for TaskFixture {
    fn identify_page(&self) -> Option<[u8; IDENTIFY_BYTES]> { None }
    fn execute_taskfile(&self, _taskfile: Taskfile, data: &mut [u8], _timeout_ms: u32)
        -> block::KResult<TaskfileResult>
    {
        data.fill(0x5a);
        Ok(self.result)
    }
    fn max_transfer_bytes(&self) -> usize { 1024 }
}

struct BlockFixture;

impl block::BlockDevice for BlockFixture {
    fn block_size(&self) -> u32 { 512 }
    fn capacity_blocks(&self) -> u64 { 1 }
    fn submit_sync(&self, _request: &mut block::BlockRequest) -> block::KResult<()> { Err(block::BlockError::Eopnotsupp) }
    fn flush(&self) -> block::KResult<()> { Err(block::BlockError::Eopnotsupp) }
}

#[test]
fn ata_16_preserves_extended_taskfile_register_order() {
    let cdb = [0x85, 0x0d, 0x2e, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x40, 0xec, 0];
    let task = crate::sat::decode_ata_16(&cdb).expect("valid ATA PASS-THROUGH(16)");
    assert!(task.extend);
    assert_eq!(task.hob_feature, 0xaa);
    assert_eq!(task.hob_nsect, 0xcc);
    assert_eq!(task.hob_lbal, 0xee);
    assert_eq!(task.hob_lbam, 0x02);
    assert_eq!(task.hob_lbah, 0x04);
    assert_eq!(task.feature, 0xbb);
    assert_eq!(task.nsect, 0xdd);
    assert_eq!(task.lbal, 0x01);
    assert_eq!(task.lbam, 0x03);
    assert_eq!(task.lbah, 0x05);
    assert_eq!(task.device, 0x40);
    assert_eq!(task.command, 0xec);
}

#[test]
fn ata_12_preserves_taskfile_register_order() {
    let cdb = [0xa1, 0x08, 0x2e, 0xaa, 0xbb, 0x01, 0x02, 0x03, 0x40, 0xec, 0, 0];
    let task = crate::sat::decode_ata_12(&cdb).expect("valid ATA PASS-THROUGH(12)");
    assert!(!task.extend);
    assert_eq!(task.feature, 0xaa);
    assert_eq!(task.nsect, 0xbb);
    assert_eq!(task.lbal, 0x01);
    assert_eq!(task.lbam, 0x02);
    assert_eq!(task.lbah, 0x03);
    assert_eq!(task.device, 0x40);
    assert_eq!(task.command, 0xec);
    assert_eq!(task.auxiliary, 0);
}

#[test]
fn ata_32_preserves_extended_taskfile_registers_and_auxiliary() {
    let mut cdb = [0u8; 32];
    cdb[0] = 0x7f;
    cdb[7] = 24;
    cdb[8..10].copy_from_slice(&0x1ff0u16.to_be_bytes());
    cdb[10] = 0x0d;
    cdb[11] = 0x2e;
    cdb[14] = 0x04;
    cdb[15] = 0x02;
    cdb[16] = 0xee;
    cdb[17] = 0x05;
    cdb[18] = 0x03;
    cdb[19] = 0x01;
    cdb[20] = 0xaa;
    cdb[21] = 0xbb;
    cdb[22] = 0xcc;
    cdb[23] = 0xdd;
    cdb[24] = 0x40;
    cdb[25] = 0xec;
    cdb[28..32].copy_from_slice(&0x1234_5678u32.to_be_bytes());
    let task = crate::sat::decode_ata_32(&cdb).expect("valid ATA PASS-THROUGH(32)");
    assert!(task.extend);
    assert_eq!(task.hob_feature, 0xaa);
    assert_eq!(task.hob_nsect, 0xcc);
    assert_eq!(task.hob_lbal, 0xee);
    assert_eq!(task.hob_lbam, 0x02);
    assert_eq!(task.hob_lbah, 0x04);
    assert_eq!(task.feature, 0xbb);
    assert_eq!(task.nsect, 0xdd);
    assert_eq!(task.lbal, 0x01);
    assert_eq!(task.lbam, 0x03);
    assert_eq!(task.lbah, 0x05);
    assert_eq!(task.device, 0x40);
    assert_eq!(task.command, 0xec);
    assert_eq!(task.auxiliary, 0x1234_5678);
}

#[test]
fn sat_transport_executes_ata_32() {
    let device: Arc<dyn Device> = Arc::new(TaskFixture { result: result(0x50) });
    let transport = crate::scsi_transport(Arc::new(BlockFixture), device);
    let mut cdb = [0u8; 32];
    cdb[0] = 0x7f;
    cdb[7] = 24;
    cdb[8..10].copy_from_slice(&0x1ff0u16.to_be_bytes());
    cdb[10] = 0x08;
    cdb[11] = 0x2e;
    cdb[25] = 0xec;
    let command = scsi::Command::new(&cdb).expect("ATA32 command");
    let mut data = [0u8; 512];
    let completion = transport.execute(scsi::Lun::ZERO, &command, &mut data, scsi::DataDirection::FromDevice)
        .expect("completed ATA32 command");
    assert_eq!(completion.status(), 0x02);
    assert_eq!(completion.resid(), 0);
    assert_eq!(data[0], 0x5a);
}

#[test]
fn sat_ck_cond_keeps_successful_data_and_ata_return_registers() {
    let device: Arc<dyn Device> = Arc::new(TaskFixture { result: result(0x50) });
    let transport = crate::scsi_transport(Arc::new(BlockFixture), device);
    let command = scsi::Command::new(&[0x85, 0x08, 0x2e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xec, 0])
        .expect("ATA16 command");
    let mut data = [0u8; 512];
    let completion = transport.execute(scsi::Lun::ZERO, &command, &mut data, scsi::DataDirection::FromDevice)
        .expect("completed SAT command");
    assert_eq!(completion.status(), 0x02);
    assert_eq!(completion.resid(), 0);
    assert_eq!(data[0], 0x5a);
    assert_eq!(completion.sense()[0..4], [0x72, 0x01, 0, 0x1d]);
    assert_eq!(completion.sense()[8..10], [0x09, 0x0c]);
    assert_eq!(completion.sense()[21], 0x50);
}

#[test]
fn sat_ata_error_preserves_a_full_residual_and_return_descriptor() {
    let device: Arc<dyn Device> = Arc::new(TaskFixture { result: TaskfileResult {
        status: 0x51, error: 0x10, ..result(0x50)
    } });
    let transport = crate::scsi_transport(Arc::new(BlockFixture), device);
    let command = scsi::Command::new(&[0x85, 0x08, 0x2e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xec, 0])
        .expect("ATA16 command");
    let mut data = [0u8; 512];
    let completion = transport.execute(scsi::Lun::ZERO, &command, &mut data, scsi::DataDirection::FromDevice)
        .expect("completed SAT command");
    assert_eq!(completion.status(), 0x02);
    assert_eq!(completion.resid(), 512);
    assert_eq!(completion.sense()[0..4], [0x72, 0x05, 0x21, 0]);
    assert_eq!(completion.sense()[8..10], [0x09, 0x0c]);
    assert_eq!(completion.sense()[21], 0x51);
}

#[test]
fn legacy_adapters_copy_taskfile_results_back_to_their_linux_objects() {
    let device = TaskFixture { result: result(0x50) };
    let mut command = [0xec, 0, 0, 1];
    let mut page = [0u8; 512];
    assert!(crate::drive_cmd(&device, &mut command, &mut page).expect("completed drive command"));
    assert_eq!(command, [0x50, 0, 0x7f, 1]);
    assert_eq!(page[0], 0x5a);

    let mut task = [0xe5, 0, 0, 0, 0, 0, 0x40];
    assert!(crate::drive_task(&device, &mut task).expect("completed drive task"));
    assert_eq!(task, [0x50, 0, 0x7f, 0, 0, 0, 0x40]);
}
