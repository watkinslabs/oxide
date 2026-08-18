//! Linux legacy HDIO raw-command adapters over the shared taskfile owner.

use block::{BlockError, KResult};

use crate::{Device, Protocol, Taskfile};

/// Linux `HDIO_DRIVE_TASK` command number. # C: O(1)
pub const HDIO_DRIVE_TASK: u64 = 0x031e;
/// Linux `HDIO_DRIVE_CMD` command number. # C: O(1)
pub const HDIO_DRIVE_CMD: u64 = 0x031f;
/// Legacy drive-command register header size. # C: O(1)
pub const DRIVE_CMD_BYTES: usize = 4;
/// Legacy drive-task register payload size. # C: O(1)
pub const DRIVE_TASK_BYTES: usize = 7;
/// ATA sector size used by the legacy drive-command ABI. # C: O(1)
pub const LEGACY_SECTOR_BYTES: usize = 512;
/// Legacy ioctl command timeout. # C: O(1)
pub const LEGACY_TIMEOUT_MS: u32 = 10_000;

const ATA_SMART: u8 = 0xb0;
const ATA_SMART_LBAM_PASS: u8 = 0x4f;
const ATA_SMART_LBAH_PASS: u8 = 0xc2;
const DEVICE_SELECT_MASK: u8 = 0x4f;

/// Bytes appended after a legacy drive-command register header. # C: O(1)
pub const fn drive_cmd_data_bytes(args: &[u8; DRIVE_CMD_BYTES]) -> usize {
    args[3] as usize * LEGACY_SECTOR_BYTES
}

/// Execute `HDIO_DRIVE_CMD`, updating its three returned status registers.
/// A completed ATA error is returned as `Ok(false)` after those registers are
/// preserved; only a transport failure is a `KResult` error. # C: one command
pub fn drive_cmd(device: &dyn Device, args: &mut [u8; DRIVE_CMD_BYTES], data: &mut [u8]) -> KResult<bool> {
    if data.len() != drive_cmd_data_bytes(args) { return Err(BlockError::Einval); }
    let mut taskfile = Taskfile::non_data(args[0]);
    taskfile.feature = args[2];
    taskfile.nsect = args[1];
    if !data.is_empty() { taskfile.protocol = Protocol::PioIn; }
    if args[0] == ATA_SMART {
        taskfile.nsect = args[3];
        taskfile.lbal = args[1];
        taskfile.lbam = ATA_SMART_LBAM_PASS;
        taskfile.lbah = ATA_SMART_LBAH_PASS;
    }
    let result = device.execute_taskfile(taskfile, data, LEGACY_TIMEOUT_MS)?;
    args[0] = result.status;
    args[1] = result.error;
    args[2] = result.nsect;
    Ok(!result.failed())
}

/// Execute `HDIO_DRIVE_TASK`, replacing its input taskfile with the returned
/// status/error/register image. # C: one command
pub fn drive_task(device: &dyn Device, args: &mut [u8; DRIVE_TASK_BYTES]) -> KResult<bool> {
    let taskfile = Taskfile {
        command: args[0], feature: args[1], nsect: args[2], lbal: args[3], lbam: args[4], lbah: args[5],
        device: args[6] & DEVICE_SELECT_MASK, protocol: Protocol::NonData, extend: false, auxiliary: 0,
        hob_feature: 0, hob_nsect: 0, hob_lbal: 0, hob_lbam: 0, hob_lbah: 0,
    };
    let result = device.execute_taskfile(taskfile, &mut [], LEGACY_TIMEOUT_MS)?;
    args[0] = result.status;
    args[1] = result.error;
    args[2] = result.nsect;
    args[3] = result.lbal;
    args[4] = result.lbam;
    args[5] = result.lbah;
    args[6] = result.device;
    Ok(!result.failed())
}
