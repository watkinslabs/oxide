//! Which node a loop request arrived on, and which commands belong to it.
//!
//! The shim above is compiled only for the kernel target, so a test written
//! inside it would silently not exist. These two decisions are the ones a
//! shim can get wrong in a way nothing else would notice — answering a block
//! device's size ioctl as if it were a loop command, or claiming a command
//! that belongs to another driver — so they live here, ungated and tested.

use crate::uapi::{LOOP_CONFIGURE, LOOP_CTL_ADD, LOOP_CTL_GET_FREE, LOOP_CTRL_MINOR, LOOP_MAJOR,
                  LOOP_SET_FD, MISC_MAJOR};

/// What a device node is, as far as this driver is concerned.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Node {
    /// `/dev/loop-control`.
    Control,
    /// `/dev/loopN`. The minor IS the device number, which is what makes a
    /// hand-`mknod`ed node work without consulting any table.
    Device(u32),
    /// Something else entirely; this driver answers nothing for it.
    Other,
}

/// Classify a node from the kind and device number the VFS reports.
///
/// A character node is only ours at the control device's exact number, and a
/// block node only under the loop major. Everything else — including a
/// character node that happens to share the loop major, and a block node at
/// the control device's minor — is somebody else's.
/// # C: O(1)
pub fn classify(is_char: bool, major: u32, minor: u32) -> Node {
    match (is_char, major) {
        (true, MISC_MAJOR) if minor == LOOP_CTRL_MINOR => Node::Control,
        (false, LOOP_MAJOR) => Node::Device(minor),
        _ => Node::Other,
    }
}

/// Whether `cmd` is one of the device ioctls this driver owns.
///
/// The range is closed on both ends and covers nothing else: a size or
/// discard ioctl arriving on `/dev/loopN` belongs to the block layer, and
/// claiming it here would answer it with the wrong thing entirely.
/// # C: O(1)
pub fn is_device_command(cmd: u32) -> bool { (LOOP_SET_FD..=LOOP_CONFIGURE).contains(&cmd) }

/// Whether `cmd` is one of the three index ioctls.
///
/// The control node answers every command sent to it — an unrecognised one
/// with `ENOSYS` — so this exists to name the three that do something, not to
/// gate the node. # C: O(1)
pub fn is_control_command(cmd: u32) -> bool { (LOOP_CTL_ADD..=LOOP_CTL_GET_FREE).contains(&cmd) }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uapi::{LOOP_CHANGE_FD, LOOP_CLR_FD, LOOP_CTL_REMOVE, LOOP_GET_STATUS64,
                      LOOP_SET_BLOCK_SIZE, LOOP_SET_STATUS};

    /// The control node is one exact character device, and nothing else
    /// reaches it — not the same minor on the block side, not the same major
    /// at another minor.
    #[test]
    fn only_the_exact_control_device_is_the_control_node() {
        assert_eq!(classify(true, MISC_MAJOR, LOOP_CTRL_MINOR), Node::Control);
        assert_eq!(classify(true, MISC_MAJOR, 235), Node::Other, "another misc device");
        assert_eq!(classify(false, MISC_MAJOR, LOOP_CTRL_MINOR), Node::Other, "block, not char");
        assert_eq!(classify(true, LOOP_MAJOR, LOOP_CTRL_MINOR), Node::Other, "wrong major");
    }

    /// A block node under the loop major names the device its minor is, so a
    /// node created by hand with `mknod` addresses the same device the driver
    /// published.
    #[test]
    fn a_block_node_names_the_device_its_minor_is() {
        assert_eq!(classify(false, LOOP_MAJOR, 0), Node::Device(0));
        assert_eq!(classify(false, LOOP_MAJOR, 7), Node::Device(7));
        assert_eq!(classify(false, LOOP_MAJOR, 4095), Node::Device(4095));
        assert_eq!(classify(true, LOOP_MAJOR, 0), Node::Other, "char, not block");
        assert_eq!(classify(false, 8, 0), Node::Other, "a SCSI disk is not ours");
    }

    /// Every device command is claimed...
    #[test]
    fn every_device_command_is_claimed() {
        for cmd in [LOOP_SET_FD, LOOP_CLR_FD, LOOP_SET_STATUS, LOOP_GET_STATUS64,
                    LOOP_CHANGE_FD, LOOP_SET_BLOCK_SIZE, LOOP_CONFIGURE] {
            assert!(is_device_command(cmd), "{cmd:#x}");
        }
    }

    /// ...and nothing else is. A size ioctl arriving on `/dev/loopN` belongs
    /// to the block layer; answering it here would return a loop result to a
    /// caller asking how big the device is.
    #[test]
    fn a_block_layer_command_on_a_loop_node_is_not_claimed() {
        // BLKGETSIZE64, BLKSSZGET, BLKDISCARD, BLKFLSBUF — the commands a
        // filesystem and blkid send to the same node.
        for cmd in [0x8008_1272u32, 0x1268, 0x1277, 0x1261, 0x125F] {
            assert!(!is_device_command(cmd), "{cmd:#x}");
        }
        // Neither are the control commands: they arrive on a different node.
        assert!(!is_device_command(LOOP_CTL_ADD));
        assert!(!is_device_command(LOOP_CTL_GET_FREE));
        // Nor the command immediately outside each end of the range.
        assert!(!is_device_command(LOOP_SET_FD - 1));
        assert!(!is_device_command(LOOP_CONFIGURE + 1));
    }

    #[test]
    fn the_three_index_commands_are_named_and_nothing_else_is() {
        for cmd in [LOOP_CTL_ADD, LOOP_CTL_REMOVE, LOOP_CTL_GET_FREE] {
            assert!(is_control_command(cmd), "{cmd:#x}");
        }
        assert!(!is_control_command(LOOP_CTL_ADD - 1));
        assert!(!is_control_command(LOOP_CTL_GET_FREE + 1));
        assert!(!is_control_command(LOOP_SET_FD));
    }
}
